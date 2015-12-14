CC = gcc            
CFLAGS = -g -Wall
TESTS = tests

# pattern rule for object files
%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

rvm_test1: seqsrchst.o steque.o rvm.o rvm_test1.o
	$(CC) -o rvm_test1 seqsrchst.o steque.o rvm.o rvm_test1.o
	rm -f *.o

rvm_test2: seqsrchst.o steque.o rvm.o rvm_test2.o
	$(CC) -o rvm_test2 seqsrchst.o steque.o rvm.o rvm_test2.o
	rm -f *.o

rvm_test3: seqsrchst.o steque.o rvm.o rvm_test3.o
	$(CC) -o rvm_test3 seqsrchst.o steque.o rvm.o rvm_test3.o
	rm -f *.o

rvm_test4: seqsrchst.o steque.o rvm.o rvm_test4.o
	$(CC) -o rvm_test4 seqsrchst.o steque.o rvm.o rvm_test4.o
	rm -f *.o

rvm_test5: seqsrchst.o steque.o rvm.o rvm_test5.o
	$(CC) -o rvm_test5 seqsrchst.o steque.o rvm.o rvm_test5.o
	rm -f *.o

rvm_test6: seqsrchst.o steque.o rvm.o rvm_test6.o
	$(CC) -o rvm_test6 seqsrchst.o steque.o rvm.o rvm_test6.o
	rm -f *.o

rvm_test7: seqsrchst.o steque.o rvm.o rvm_test7.o
	$(CC) -o rvm_test7 seqsrchst.o steque.o rvm.o rvm_test7.o
	rm -f *.o

clean:
	rm -f *.o rvm_test1 rvm_test2 rvm_test3 rvm_test4 rvm_test5 \
		  rvm_test6 rvm_test7
	rm -f core
