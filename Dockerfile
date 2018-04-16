FROM ubuntu:17.10
RUN apt-get update && apt install -y apt-transport-https ca-certificates software-properties-common && \
    apt-key adv --keyserver keyserver.ubuntu.com --recv-keys D4284CDD && \
    echo "deb https://repo.iovisor.org/apt/artful artful main" | tee /etc/apt/sources.list.d/iovisor.list && \
    apt-get update &&\
    apt-get install -y bcc-tools libbcc-examples linux-headers-generic golang git build-essential cmake llvm-3.8 libclang-3.8-dev\
    bison python zlib1g-dev libelf-dev flex libedit-dev && \
    git clone https://github.com/iovisor/bcc.git && \
    mkdir bcc/build/
WORKDIR /bcc/build/
RUN git checkout v0.5.0 && \
    cmake .. -DCMAKE_INSTALL_PREFIX=/usr && \
    make && make install && \
    mkdir -p /go/src/github.com/cpg1111 /go/pkg/ /go/bin/
ENV GOPATH /go/
RUN go get github.com/golang/dep/cmd/...
COPY . /go/src/github.com/cpg1111/pprof-ebpf/
