srcdir = ./src/
cc = gcc
target = arptool
src = $(srcdir)*.*

$(target):$(src)
	$(cc) -o $(target) $(srcdir)/*.c -lpthread

clean:
	rm -rf $(target)	

nihao
