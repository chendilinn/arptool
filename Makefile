srcdir = ./src/
cc = gcc
target = arptool
src = $(srcdir)*.*

$(target):$(src)
	$(cc) -o $@ $(srcdir)/*.c -lpthread

clean:
	rm -rf $(target)	
