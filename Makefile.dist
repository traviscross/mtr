
#
# This is an attempt on simplifying the compilation of mtr to a simple "make". 
#

firstrule: 
	./configure 
	$(MAKE)

clean: 
	rm -f *.o *~ core

distclean: clean
	rm -f mtr config.cache config.status config.log \
	          stamp-h stamp-h[0-9]* TAGS ID

