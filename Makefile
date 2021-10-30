LDLIBS = -lnetfilter_queue -lnet

all: netfilter-test

netfilter-test: netfilter-test.c

clean:
	rm -f netfilter-test *.o

remake: clean all
