CFLAGS=-g -O2 -Wall
all: fixed_rtunnel dynamic_rtunnel

fixed_rtunnel: fixed.o supervisor.o listener.o misc.o tls.o log.o common/blockmem.o
	gcc -o $@ $^ -lgnutls -lpthread

dynamic_rtunnel: dynamic.o connector.o misc.o tls.o log.o
	gcc -o $@ $^ -lgnutls -lpthread

clean:
	rm -f *.o common/*.o core fixed_rtunnel dynamic_rtunnel

package: clean
	tar -zhcf /tmp/rtunnel.tgz .
