# rzpipe for Python

Interact with rizin using the #!pipe command or in standalone scripts
that communicate with local or remote r2 via pipe, tcp or http.

## Installation

```
$ pip install rzpipe
```

or

```
$ pip3 install rzpipe
```

## Usage example:

```python
import rzpipe

pipe = rzpipe.open("/bin/ls")
pipe.cmd('aa')
print(pipe.cmd("afl"))
print(pipe.cmdj("aflj"))            # evaluates JSONs and returns an object
print(pipe.cmdj("ij").core.format)  # shows file format
pipe.quit()
```
