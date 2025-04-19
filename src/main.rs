use clap::Parser;
use colored::*;
use notify::{RecursiveMode, Watcher};
use regex::bytes::Regex;
use serde_json::Value;
use std::io::Error as IoError;
use std::io::Result;
use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, BufReader};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Number of lines to display
    #[arg(short = 'n', long, default_value = "10")]
    lines: usize,

    /// Follow file changes
    #[arg(short = 'f', long)]
    follow: bool,

    /// Parse and pretty print each line as JSON
    #[arg(long)]
    jsonl: bool,

    /// Use NUL byte as delimiter instead of newline
    #[arg(short = 'z', default_value_t = false)]
    zero_terminated: bool,

    /// Use a custom delimiter (overrides -z if specified)
    #[arg(short = 'd', long)]
    delimiter: Option<String>,

    /// Print line numbers
    #[arg(short = 'N', default_value_t = false)]
    line_numbers: bool,

    /// Print byte offsets
    #[arg(short = 'B', default_value_t = false)]
    byte_offsets: bool,

    /// Enable colored output
    #[arg(short = 'C', long, default_value_t = false)]
    color: bool,

    /// Print file content as bytes
    #[arg(long)]
    bin: bool,

    /// Highlight pattern in binary mode (regular expression)
    #[arg(long)]
    pattern: Option<String>,

    /// File to tail (if not specified, reads from stdin)
    file: Option<PathBuf>,
}

struct LineInfo {
    content: Vec<u8>,
    line_number: usize,
    byte_offset: usize,
}

fn print_line(line: &LineInfo, args: &Args) {
    let line_str = String::from_utf8_lossy(&line.content);
    let prefix = if args.line_numbers || args.byte_offsets {
        let mut parts = Vec::new();
        if args.line_numbers {
            let line_num = if args.color {
                format!("{}", line.line_number).bold().cyan().to_string()
            } else {
                format!("{}", line.line_number)
            };
            parts.push(line_num);
        }
        if args.byte_offsets {
            let byte_offset = if args.color {
                format!("0x{:x}", line.byte_offset)
                    .bold()
                    .magenta()
                    .to_string()
            } else {
                format!("0x{:x}", line.byte_offset)
            };
            parts.push(byte_offset);
        }
        format!("[{}] ", parts.join(" "))
    } else {
        String::new()
    };

    if args.jsonl {
        match serde_json::from_str::<Value>(&line_str) {
            Ok(json) => {
                let json_str =
                    serde_json::to_string_pretty(&json).unwrap_or_else(|_| line_str.to_string());
                if args.color {
                    // Color JSON output properly
                    let mut result = String::new();
                    let mut in_string = false;
                    let mut current_string = String::new();
                    let mut is_key = false;
                    let mut current_number = String::new();
                    let mut in_number = false;
                    let mut is_float = false;
                    let mut chars = json_str.chars().peekable();

                    while let Some(c) = chars.next() {
                        if c == '"' {
                            if in_string {
                                // End of string
                                if is_key {
                                    result.push_str(&current_string.bold().yellow().to_string());
                                } else {
                                    result.push_str(&current_string.yellow().to_string());
                                }
                                result.push('"');
                                current_string.clear();
                                is_key = false;
                            } else {
                                // Start of string
                                result.push('"');
                                is_key = result.ends_with(": \"");
                            }
                            in_string = !in_string;
                        } else if in_string {
                            current_string.push(c);
                        } else if c.is_digit(10) || c == '.' || c == '-' || c == 'e' || c == 'E' {
                            if !in_number {
                                in_number = true;
                                current_number.clear();
                                is_float = false;
                            }
                            if c == '.' || c == 'e' || c == 'E' {
                                is_float = true;
                            }
                            current_number.push(c);
                        } else {
                            if in_number {
                                if is_float {
                                    result.push_str(&current_number.cyan().to_string());
                                } else {
                                    result.push_str(&current_number.blue().to_string());
                                }
                                current_number.clear();
                                in_number = false;
                                is_float = false;
                            }

                            // Handle boolean and null values
                            if c == 't' && chars.peek() == Some(&'r') {
                                result.push_str(&"true".bold().green().to_string());
                                chars.next(); // r
                                chars.next(); // u
                                chars.next(); // e
                            } else if c == 'f' && chars.peek() == Some(&'a') {
                                result.push_str(&"false".bold().green().to_string());
                                chars.next(); // a
                                chars.next(); // l
                                chars.next(); // s
                                chars.next(); // e
                            } else if c == 'n' && chars.peek() == Some(&'u') {
                                result.push_str(&"null".bold().green().to_string());
                                chars.next(); // u
                                chars.next(); // l
                                chars.next(); // l
                            } else {
                                match c {
                                    ':' => result.push_str(&":".white().to_string()),
                                    ',' => result.push_str(&",".white().to_string()),
                                    '{' => result.push_str(&"{".white().to_string()),
                                    '}' => result.push_str(&"}".white().to_string()),
                                    '[' => result.push_str(&"[".white().to_string()),
                                    ']' => result.push_str(&"]".white().to_string()),
                                    _ => result.push(c),
                                }
                            }
                        }
                    }
                    // Handle any remaining number
                    if in_number {
                        if is_float {
                            result.push_str(&current_number.cyan().to_string());
                        } else {
                            result.push_str(&current_number.blue().to_string());
                        }
                    }
                    println!("{}{}", prefix, result);
                } else {
                    println!("{}{}", prefix, json_str);
                }
            }
            Err(_) => println!("{}{}", prefix, line_str),
        }
    } else {
        println!("{}{}", prefix, line_str);
    }
}

async fn read_delimited_chunks<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    delimiter: &[u8],
) -> Result<Vec<LineInfo>> {
    let mut chunks = Vec::new();
    let mut buffer = Vec::new();
    let mut temp = vec![0; 1024];
    let mut delimiter_pos = 0;
    let mut line_number = 1;
    let mut byte_offset = 0;

    loop {
        match reader.read(&mut temp).await {
            Ok(0) => break,
            Ok(n) => {
                let slice = &temp[..n];
                for &byte in slice {
                    byte_offset += 1;
                    if byte == delimiter[delimiter_pos] {
                        delimiter_pos += 1;
                        if delimiter_pos == delimiter.len() {
                            if !buffer.is_empty() {
                                chunks.push(LineInfo {
                                    content: buffer,
                                    line_number,
                                    byte_offset: byte_offset - delimiter.len(),
                                });
                                buffer = Vec::new();
                                line_number += 1;
                            }
                            delimiter_pos = 0;
                        }
                    } else {
                        if delimiter_pos > 0 {
                            buffer.extend_from_slice(&delimiter[..delimiter_pos]);
                            delimiter_pos = 0;
                        }
                        buffer.push(byte);
                    }
                }
            }
            Err(e) => return Err(e),
        }
    }

    if delimiter_pos > 0 {
        buffer.extend_from_slice(&delimiter[..delimiter_pos]);
    }
    if !buffer.is_empty() {
        chunks.push(LineInfo {
            content: buffer,
            line_number,
            byte_offset,
        });
    }

    Ok(chunks)
}

async fn print_last_n_lines(file: File, args: &Args) -> Result<()> {
    let mut buffer = Vec::with_capacity(args.lines);

    let delimiter = if let Some(d) = &args.delimiter {
        d.as_bytes()
    } else if args.zero_terminated {
        &[0]
    } else {
        b"\n"
    };

    if args.delimiter.is_some() || args.zero_terminated {
        let mut reader = file;
        let chunks = read_delimited_chunks(&mut reader, delimiter).await?;
        for chunk in chunks {
            buffer.push(chunk);
            if buffer.len() > args.lines {
                buffer.remove(0);
            }
        }
    } else {
        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        let mut line_number = 1;
        let mut byte_offset = 0;

        while let Some(line) = lines.next_line().await? {
            let line_len = line.len();
            byte_offset += line_len + 1; // +1 for newline
            buffer.push(LineInfo {
                content: line.into_bytes(),
                line_number,
                byte_offset: byte_offset - line_len - 1,
            });
            if buffer.len() > args.lines {
                buffer.remove(0);
            }
            line_number += 1;
        }
    }

    for line in buffer {
        print_line(&line, args);
    }
    Ok(())
}

async fn print_last_n_bytes(file: File, args: &Args) -> Result<()> {
    let mut buffer = Vec::with_capacity(args.lines * 16); // Assuming 16 bytes per line
    let mut reader = BufReader::new(file);
    let mut offset = 0;

    let pattern = args.pattern.as_ref().map(|p| Regex::new(p).unwrap());
    let mut match_positions = Vec::new();

    loop {
        let mut chunk = vec![0; 16];
        match reader.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                buffer.push((offset, chunk[..n].to_vec()));
                if buffer.len() > args.lines {
                    buffer.remove(0);
                }
                offset += n;
            }
            Err(e) => return Err(e),
        }
    }

    // Pre-process all bytes to find matches
    let all_bytes: Vec<u8> = buffer
        .iter()
        .flat_map(|(_, bytes)| bytes.iter().cloned())
        .collect();
    if let Some(pattern) = &pattern {
        match_positions = pattern
            .find_iter(&all_bytes)
            .map(|m| m.start()..m.end())
            .collect();
    }

    let mut current_pos = 0;
    for (offset, bytes) in buffer {
        if args.byte_offsets {
            let offset_str = if args.color {
                format!("0x{:08x}:", offset).bold().magenta().to_string()
            } else {
                format!("0x{:08x}:", offset)
            };
            print!("{} ", offset_str);
        }

        // Print bytes in hex
        for (i, &byte) in bytes.iter().enumerate() {
            if i > 0 && i % 2 == 0 {
                print!(" ");
            }
            let hex_str = format!("{:02x}", byte);
            if args.color {
                if let Some(_pattern) = &pattern {
                    let is_match = match_positions
                        .iter()
                        .any(|range| range.contains(&current_pos));
                    if is_match {
                        print!("{}", hex_str.bold().red());
                    } else {
                        print!("{}", hex_str.blue());
                    }
                } else {
                    print!("{}", hex_str.blue());
                }
            } else {
                print!("{}", hex_str);
            }
            current_pos += 1;
        }

        // Print padding for incomplete lines
        if bytes.len() < 16 {
            for _ in 0..(16 - bytes.len()) {
                print!("   ");
            }
        }

        // Print ASCII representation
        print!("  ");
        current_pos -= bytes.len(); // Reset position for ASCII printing
        for &byte in &bytes {
            if byte >= 32 && byte <= 126 {
                let char_str = format!("{}", byte as char);
                if args.color {
                    if let Some(_pattern) = &pattern {
                        let is_match = match_positions
                            .iter()
                            .any(|range| range.contains(&current_pos));
                        if is_match {
                            print!("{}", char_str.bold().red());
                        } else {
                            print!("{}", char_str.yellow());
                        }
                    } else {
                        print!("{}", char_str.yellow());
                    }
                } else {
                    print!("{}", char_str);
                }
            } else {
                print!(".");
            }
            current_pos += 1;
        }
        println!();
    }

    Ok(())
}

async fn follow_file(args: &Args) -> Result<()> {
    let (tx, rx) = channel();
    let mut watcher = notify::recommended_watcher(move |res| {
        if let Ok(event) = res {
            tx.send(event).unwrap();
        }
    })
    .map_err(|e| IoError::new(std::io::ErrorKind::Other, e))?;

    let file_path = args.file.as_ref().unwrap();
    watcher
        .watch(file_path, RecursiveMode::NonRecursive)
        .map_err(|e| IoError::new(std::io::ErrorKind::Other, e))?;

    let mut last_size = 0;
    let delimiter = if let Some(d) = &args.delimiter {
        d.as_bytes()
    } else if args.zero_terminated {
        &[0]
    } else {
        b"\n"
    };

    let mut line_number = 1;
    let mut byte_offset = 0;

    loop {
        let mut file = File::open(file_path).await?;
        let metadata = file.metadata().await?;
        let current_size = metadata.len();

        if current_size > last_size {
            file.seek(std::io::SeekFrom::Start(last_size)).await?;

            if args.bin {
                let mut buffer = vec![0; (current_size - last_size) as usize];
                file.read_exact(&mut buffer).await?;

                // Find all matches in the new data
                let mut match_positions = Vec::new();
                if let Some(pattern_str) = &args.pattern {
                    let pattern = Regex::new(pattern_str).unwrap();
                    match_positions = pattern
                        .find_iter(&buffer)
                        .map(|m| m.start()..m.end())
                        .collect();
                }

                // Process the new bytes in 16-byte chunks
                let mut current_pos = 0;
                for chunk in buffer.chunks(16) {
                    if args.byte_offsets {
                        let offset_str = if args.color {
                            format!("0x{:08x}:", byte_offset)
                                .bold()
                                .magenta()
                                .to_string()
                        } else {
                            format!("0x{:08x}:", byte_offset)
                        };
                        print!("{} ", offset_str);
                    }

                    // Print bytes in hex
                    for (i, &byte) in chunk.iter().enumerate() {
                        if i > 0 && i % 2 == 0 {
                            print!(" ");
                        }
                        let hex_str = format!("{:02x}", byte);
                        if args.color {
                            if !match_positions.is_empty() {
                                let is_match = match_positions
                                    .iter()
                                    .any(|range| range.contains(&current_pos));
                                if is_match {
                                    print!("{}", hex_str.bold().red());
                                } else {
                                    print!("{}", hex_str.blue());
                                }
                            } else {
                                print!("{}", hex_str.blue());
                            }
                        } else {
                            print!("{}", hex_str);
                        }
                        current_pos += 1;
                    }

                    // Print padding for incomplete lines
                    if chunk.len() < 16 {
                        for _ in 0..(16 - chunk.len()) {
                            print!("   ");
                        }
                    }

                    // Print ASCII representation
                    print!("  ");
                    current_pos -= chunk.len(); // Reset position for ASCII printing
                    for &byte in chunk {
                        if byte >= 32 && byte <= 126 {
                            let char_str = format!("{}", byte as char);
                            if args.color {
                                if !match_positions.is_empty() {
                                    let is_match = match_positions
                                        .iter()
                                        .any(|range| range.contains(&current_pos));
                                    if is_match {
                                        print!("{}", char_str.bold().red());
                                    } else {
                                        print!("{}", char_str.yellow());
                                    }
                                } else {
                                    print!("{}", char_str.yellow());
                                }
                            } else {
                                print!("{}", char_str);
                            }
                        } else {
                            print!(".");
                        }
                        current_pos += 1;
                    }
                    println!();
                    byte_offset += chunk.len();
                }
            } else if args.delimiter.is_some() || args.zero_terminated {
                let chunks = read_delimited_chunks(&mut file, delimiter).await?;
                for chunk in chunks {
                    print_line(&chunk, args);
                }
            } else {
                let reader = BufReader::new(file);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let line_len = line.len();
                    byte_offset += line_len + 1;
                    print_line(
                        &LineInfo {
                            content: line.into_bytes(),
                            line_number,
                            byte_offset: byte_offset - line_len - 1,
                        },
                        args,
                    );
                    line_number += 1;
                }
            }
        }

        last_size = current_size;

        // Wait for file changes
        if let Ok(event) = rx.recv_timeout(Duration::from_millis(100)) {
            if let notify::EventKind::Modify(_) = event.kind {
                continue;
            }
        }
    }
}

#[tokio::main]
pub async fn main() -> Result<()> {
    let args = Args::parse();

    if args.follow && args.file.is_none() {
        eprintln!("Error: Cannot follow stdin");
        std::process::exit(1);
    }

    if let Some(file_path) = &args.file {
        let file = File::open(file_path).await?;
        if args.bin {
            print_last_n_bytes(file, &args).await?;
        } else {
            print_last_n_lines(file, &args).await?;
        }

        if args.follow {
            follow_file(&args).await?;
        }
    } else {
        // Read from stdin
        let stdin = tokio::io::stdin();
        let mut reader = BufReader::new(stdin);
        let mut buffer = Vec::with_capacity(args.lines);
        let mut line_number = 1;
        let mut byte_offset = 0;
        let mut line = String::new();

        if args.bin {
            // Handle binary input from stdin
            let mut bytes = Vec::new();
            while let Ok(n) = reader.read_to_end(&mut bytes).await {
                if n == 0 {
                    break;
                }
                // Process the bytes in 16-byte chunks
                for chunk in bytes.chunks(16) {
                    if args.byte_offsets {
                        let offset_str = if args.color {
                            format!("0x{:08x}:", byte_offset)
                                .bold()
                                .magenta()
                                .to_string()
                        } else {
                            format!("0x{:08x}:", byte_offset)
                        };
                        print!("{} ", offset_str);
                    }

                    // Print bytes in hex
                    for (i, &byte) in chunk.iter().enumerate() {
                        if i > 0 && i % 2 == 0 {
                            print!(" ");
                        }
                        let hex_str = format!("{:02x}", byte);
                        if args.color {
                            print!("{}", hex_str.blue());
                        } else {
                            print!("{}", hex_str);
                        }
                    }

                    // Print padding for incomplete lines
                    if chunk.len() < 16 {
                        for _ in 0..(16 - chunk.len()) {
                            print!("   ");
                        }
                    }

                    // Print ASCII representation
                    print!("  ");
                    for &byte in chunk {
                        if byte >= 32 && byte <= 126 {
                            let char_str = format!("{}", byte as char);
                            if args.color {
                                print!("{}", char_str.yellow());
                            } else {
                                print!("{}", char_str);
                            }
                        } else {
                            print!(".");
                        }
                    }
                    println!();
                    byte_offset += chunk.len();
                }
            }
        } else {
            while reader.read_line(&mut line).await? > 0 {
                let line_len = line.trim_end().len();
                byte_offset += line_len + 1; // +1 for newline
                buffer.push(LineInfo {
                    content: line.trim_end().as_bytes().to_vec(),
                    line_number,
                    byte_offset: byte_offset - line_len - 1,
                });
                if buffer.len() > args.lines {
                    buffer.remove(0);
                }
                line_number += 1;
                line.clear();
            }

            for line in buffer {
                print_line(&line, &args);
            }
        }
    }

    Ok(())
}
