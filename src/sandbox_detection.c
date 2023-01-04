#include <stdlib.h>
#include <stdio.h>
#include "sandbox_detection.h"

// https://www.aldeid.com/wiki/X86-assembly/Instructions/sldt

unsigned long __get_ldtr_base (void)
{
	unsigned char   ldtr[5] = "\xef\xbe\xad\xde";
	unsigned long   ldt			= 0;
 
	_asm sldt ldtr
	ldt = *((unsigned long *)&ldtr[0]);
 
	return (ldt);
}


int check_sldt(void){
	unsigned int	ldt_base	= 0;
 
	ldt_base = get_ldtr_base ();
 
	printf ("\n[+] Test 2: LDT\n");
	printf ("LDT base: 0x%x\n", ldt_base);
 
	if (ldt_base == 0xdead0000) {
		return 0;
	}
 
	else {
		return -1;
	}
}