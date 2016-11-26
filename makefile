
all: syscalltable-checker

syscalltable-checker: syscalltable-checker.c
	gcc -Wall -I /usr/src/linux/include -c syscalltable-checker.c && \
	cp -f syscalltable-checker.o /lib/modules/2.4.18/kernel && \
	depmod -a

clean:
	rmmod syscalltable-checker
	rm -f syscalltable-checker.o /lib/modules/2.4.18/kernel/syscalltable-checker.o

