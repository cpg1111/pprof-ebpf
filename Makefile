KVER = $(shell uname -r)
KMAJ = $(shell echo $(KVER) | sed -e 's/^\([0-9][0-9]*\)\.[0-9][0-9]*\.[0-9][0-9]*.*/\1/')
KMIN = $(shell echo $(KVER) | sed -e 's/^[0-9][0-9]*\.\([0-9][0-9]*\)\.[0-9][0-9]*.*/\1/')
KREV = $(shell echo $(KVER) | sed -e 's/^[0-9][0-9]*\.[0-9][0-9]*\.\([0-9][0-9]*\).*/\1/')
PKGMGR = apt
UPDATE = update
INSTALL = install -y
ADDREPO = apt-key adv --keyserver
KEYSERVER = keyserver.ubuntu.com
GOPATH = ${HOME}/go/

kver_ge = $(shell \
echo test | awk '{if($(KMAJ) < $(1)) {print 0} else { \
if($(KMAJ) > $(1)) {print 1} else { \
if($(KMIN) < $(2)) {print 0} else { \
if($(KMIN) > $(2)) {print 1} else { \
if($(KREV) < $(3)) {print 0} else { print 1  } \
} } } }}' \
)

.PHONY: all
all: generate build

.PHONY: get-deps
get-deps:
ifneq ($(call kver_ge,4,9,0),1)
	echo "pprof-ebpf requires kernel features found in 4.9.X and newer" && exit 1
endif

ifeq (,$(wildcard /lib/modules/$(KVER)))
	sudo ${PKGMGR} ${INSTALL} linux-headers-${KVER}
endif

ifeq (,$(wildcard /usr/share/bcc/))
	sudo ${ADDREPO} ${KEYSERVER} --recv-keys D4284CDD
	sudo ${PKGMGR} ${UPDATE}
	if ! [ -x `which git` -eq ""]; then sudo ${PKGMGR} ${INSTALL} git; fi
	if ! [ `which go` -eq "" ]; then sudo ${PKGMGR} ${INSTALL} golang; fi
	if ! [ `which clang` -eq "" ]; then sudo ${PKGMGR} ${INSTALL} \
		llvm-3.8 libclang-3.8-dev bison \
		libelf-dev flex libedit-dev zlib1g-dev \
		automake libtool;\
	fi
	if ! [ `which cmake` -eq "" ]; then sudo ${PKGMGR} ${INSTALL} cmake; fi
	if ! [ `which python` -eq "" ]; then sudo ${PKGMGR} ${INSTALL} python; fi
	git clone https://github.com/iovisor/bcc.git \
	/usr/share/bcc/ && \
	cd /usr/share/bcc && git checkout v0.5.0 && \
	mkdir ./build && cd ./build/ && \
	cmake .. -DCMAKE_INSTALL_PREFIX=/usr && \
	make && \
	sudo make install;
endif

ifeq (,$(wildcard $(GOPATH)/bin/dep))
	go get github.com/golang/dep
endif

ifeq (,$(wildcard /usr/local/bin/protoc))
	cd /tmp/ && \
	git clone https://github.com/google/protobuf.git && \
	cd protobuf && \
	./autogen.sh && \
	./configure && make && make install
endif

.PHONY: build
build:
ifneq ($(call kver_ge,4,9,0),1)
	echo "pprof-ebpf requires kernel features found in 4.9.X and newer" && exit 1
endif

ifeq (,$(wildcard ./vendor/github.com/))
	dep ensure
endif
ifeq (,$(wildcard ./vendor/github.com/google/pprof/proto/profile.pb.go))
	cd ./vendor/github.com/google/pprof/proto/ && \
	protoc ./profile.proto
endif
	mkdir -p ./build/
	sudo -E go build -o ./build/pprof-ebpf ./main.go

docker-build:
ifneq ($(call kver_ge,4,9,0),1)
	echo "pprof-ebpf requires kernel features found in 4.9.X and newer" && exit 1
endif

	GOPATH=/go/ go env
ifeq (,$(wildcard ./vendor/github.com/))
	GOPATH=/go/ dep ensure
endif
ifeq (,$(wildcard ./vendor/github.com/google/pprof/proto/profile.pb.go))
	cd ./vendor/github.com/google/pprof/proto/ && \
	protoc ./profile.proto
endif
	mkdir -p ./build/
	GOPATH=/go/ go build -o ./build/pprof-ebpf ./main.go

.PHONY: test
test:
ifneq ($(call kver_ge,4,9,0),1)
	echo "pprof-ebpf requires kernel features found in 4.9.X and newer" && exit 1
endif

	go test -v ./...

.PHONY: clean
clean:
	rm pprof-ebpf

.PHONY: install
install:
ifneq ($(call kver_ge,4,9,0),1)
	echo "pprof-ebpf requires kernel features found in 4.9.X and newer" && exit 1
endif

	go install .

.PHONY: uninstall
uninstall:
	rm `which pprof-ebpf`

.PHONY: generate
generate:
	rm pkg/cpu/bpf.go pkg/heap/bpf.go
	go generate ./...
