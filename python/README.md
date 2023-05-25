# rzpipe for Python

Interact with rizin using the `#!pipe` command or in standalone scripts
that communicate with local or remote rizin via pipe, tcp or http.

## Installation

```sh
$ pip install rzpipe
```

or

```sh
$ pip3 install rzpipe
```

## Usage example:

```python
import rzpipe

pipe = rzpipe.open("/bin/ls")
pipe.cmd('aa')
print(pipe.cmd("afl"))
print(pipe.cmdj("aflj"))            # parses the JSON and returns a dict (note the lowercase j)
print(pipe.cmdJ("ij").core.format)  # parses the JSON and returns a namedtuple (note the uppercase J)
pipe.quit()
```
