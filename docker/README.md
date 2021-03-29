# fcd-docker

a dockerfile for the FCD decompiler (https://github.com/zneak/fcd)

## Usage

It takes a while to build! Took about 5 minutes on my laptop.

```sh
# build the container
docker bulid -t fcd .

# you can just use the start.sh wrapper script
./start.sh /path/to/binary
```

and it will spit out the decompiled code!
