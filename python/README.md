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

r2 = rzpipe.open("/bin/ls")
r2.cmd('aa')
print(r2.cmd("afl"))
print(r2.cmdj("aflj"))            # evaluates JSONs and returns an object
print(r2.cmdj("ij").core.format)  # shows file format
r2.quit()
```
