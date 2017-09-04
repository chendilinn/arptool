srcdir = ./src/
cc = gcc -Wall
target = arptool
src = $(srcdir)*.*

$(target):$(src)
	$(cc) -o $@ $(srcdir)/*.c -lpthread

clean:
	rm -rf $(target)	
