#include <iostream>

struct LinkStack{
	ADDRINT addr;
	struct LinkStack* next;
	struct LinkStack* pre;
};

VOID STK_Init(LinkStack *top){
	LinkStack *base = new(LinkStack);
	base -> addr = 0x0;
	top -> addr = 0x0;
	top -> next = base;
	top -> pre = NULL;
	base -> next = NULL;
	base -> pre = top;
}

VOID STK_Push(LinkStack *s, ADDRINT addr){
	LinkStack *p = new(LinkStack);
	p -> addr = addr;
	p -> pre = s;
	p -> next = s -> next;
	s -> next -> pre = p;
	s -> next = p;
}

ADDRINT STK_Pop(LinkStack *s){
	ADDRINT ret = 0x0;
	if(s -> next -> next){
		LinkStack *p = s -> next;
		s -> next = p -> next;
		p -> next -> pre = s;
		ret = p -> addr;
		free(p);
	}
	return ret;
}

BOOL STK_IsEmpty(LinkStack *s){
	if(s -> next -> next){
		return 0;
	}else{
		return 1;
	}
}

VOID STK_Show(LinkStack *s){
	LinkStack *p;
	cerr << "|-------------------------------|" << endl;
	for(p = s -> next; p -> next; p = p -> next){
		cerr << "| " << p << " | 0x" << hex << p -> addr << " |" << endl;
	}	
	cerr << "|-------------------------------|" << endl;
}