FROM ubuntu:xenial

RUN apt update
RUN apt install -y git clang-4.0 clang-4.0-dev cmake cmake-data libz-dev libcapstone3 libcapstone-dev libedit-dev libstdc++6-4.7-dev llvm-4.0 llvm-4.0-dev python-dev \
 && git clone https://github.com/zneak/fcd \
 && mkdir fcd/build && cd fcd/build \
 && CXX="clang++-4.0" CC="clang-4.0" cmake .. \
 && make -j4 

# install it into PATH
RUN cp /fcd/build/fcd /usr/bin/

CMD fcd --help