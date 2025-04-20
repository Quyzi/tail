```
Usage: tail [OPTIONS] [FILE]

Arguments:
  [FILE]  File to tail (if not specified, reads from stdin)

Options:
  -n, --lines <LINES>          Number of lines to display [default: 10]
  -f, --follow                 Follow file changes
      --jsonl                  Parse and pretty print each line as JSON
  -z                           Use NUL byte as delimiter instead of newline
  -d, --delimiter <DELIMITER>  Use a custom delimiter (overrides -z if specified)
  -N                           Print line numbers
  -B                           Print byte offsets
  -C, --color                  Enable colored output
      --bin                    Print file content as bytes
      --pattern <PATTERN>      Highlight pattern in binary mode (regular expression)
  -h, --help                   Print help
  -V, --version                Print version
```
