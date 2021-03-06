#include "pin.H"
#include "stack.H"
#include <iostream>
#include <fstream>

#define LIBC "libc.so.6" //general
#define RET 1
#define CALL 2
#define BRANCH 4

#define G_SIZE 7
#define S_LENGTH 5

#define KILL 0

#define DEBUG 1

static bool R2L_DECT = 0;
static bool THR_DECT = 0;
static bool STK_DECT = 0;
static bool CRB_DECT = 0;
static bool GOT_DECT = 0;
static bool CPR_DECT = 0;

static int c_count = 0;
static int r_count = 0;

static int g_count = 0;
static int s_count = 0;

static bool libcAcc;
static bool execAcc;
static bool beAttacked = 0;

static ADDRINT addresses[S_LENGTH+10];

static ADDRINT libcLow;
static ADDRINT libcHigh;
static ADDRINT execLow;
static ADDRINT execHigh;

static LinkStack* lstack;
static LinkStack* symbols;
static LinkStack* symbols_libc;
static LinkStack* cpra;

/* ===================================================================== */
INT32 Usage() {
	cerr << "This tool detects ROP attacks.\n"; 
	cerr << endl;
	return -1;
}
/* ===================================================================== */
// show system time 
string time(){
	struct tm nowtime;
	struct timeval tv;
	char time_now[128];
	gettimeofday(&tv, NULL);
	localtime_r(&tv.tv_sec,&nowtime);

	sprintf(time_now,"%d-%d-%d %d:%d:%d.%03d ",
		nowtime.tm_year+1900,
		nowtime.tm_mon+1,
		nowtime.tm_mday,
		nowtime.tm_hour,
		nowtime.tm_min,
		nowtime.tm_sec,
		(int)(tv.tv_usec/1000)
	);
	return (string)time_now;
}

// receive args from web-server
VOID read_opt(){
	char buf[256];
	ifstream in("/tmp/flag");
	in.getline(buf,100);
	int flag = atoi(buf);
	if(flag & 1){
		R2L_DECT = 1;
		cerr << "[+] R2L_DECT open" << endl;
	}
	if(flag & 2){
		THR_DECT = 1;
		cerr << "[+] THR_DECT open" << endl;
	}
	if(flag & 4){
		STK_DECT = 1;
		cerr << "[+] STK_DECT open" << endl;
	}
	if(flag & 8){
		CRB_DECT = 1;
		cerr << "[+] CRB_DECT open" << endl;
	}
	if(flag & 16){
		GOT_DECT = 1;
		cerr << "[+] GOT_DECT open" << endl;
	}
	if(flag & 32){
		CPR_DECT = 1;
		cerr << "[+] CPR_DECT open" << endl;
	}
}

// kill process to protect it from attack
VOID kill(){
	if(KILL){
	    cerr << "[!] process killed by Pintool." << endl;
		exit(0);
	}
}

/* ===================================================================== */
VOID ImageLoad(IMG img, VOID *v) {
	// if(DEBUG){
	// 	cerr << "Loading " << IMG_Name(img) << ", Image id = " << IMG_Id(img) << endl;
	// }
	if(IMG_Name(img).find(LIBC) != string::npos) {
		libcAcc = 1;
		libcLow = IMG_LowAddress(img);
		libcHigh = IMG_HighAddress(img);
		// if(DEBUG) cerr << "libc loaded: 0x" << hex << libcLow << " - 0x" << libcHigh << endl;
		for( SYM sym= IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym) ){
			STK_Push2(symbols_libc, SYM_Name(sym), SYM_Address(sym));
			// if(DEBUG){
				// cerr << "symbol: " << SYM_Name(sym) << " @ " ;
				// cerr << hex << "0x" << SYM_Address(sym) << endl;
			// }
		}
		// if(DEBUG) STK_Show2(symbols_libc);
	}
	if(IMG_IsMainExecutable(img)) {
		execAcc = 1;
		execLow = IMG_LowAddress(img);
		execHigh = IMG_HighAddress(img);
		// if(DEBUG) cerr << "text section: 0x" << hex << execLow << " - 0x" << execHigh << endl;

		// Forward pass over all symbols in an image
		for( SYM sym= IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym) ){
			STK_Push2(symbols, SYM_Name(sym), SYM_Address(sym));
			// if(DEBUG){
				// cerr << "symbol: " << SYM_Name(sym) << " @ " ;
				// cerr << hex << "0x" << SYM_Address(sym) << endl;				
			// }
		}
		// if(DEBUG) STK_Show2(symbols);
	}
}

VOID ImageUnload(IMG img, VOID *v) {
    // if(DEBUG){
    // 	cerr << "Unloading " << IMG_Name(img) << endl;
    // }
}

/* ===================================================================== */

VOID g_counter(){
    g_count++;
}

VOID logic(ADDRINT ip){
	g_counter();
	// only consider gadget in elf and libc
	if((ip < execHigh && ip > execLow) || (libcAcc && ip < libcHigh && ip > libcLow)){
	    addresses[s_count] = ip;
	    if(g_count > G_SIZE){
            g_count = 0;
            s_count = 0;
	    }//if g_count > glength, no gadget. reset counters.
	    else{
	        //if g_count < glength, gadget detected. Reset g_count, increment s_count,
	        // and check s_count vs slength.
	        g_count = 0;
	        s_count ++;
	        if(s_count >= S_LENGTH){
	        	beAttacked = 1;
				cerr << "[attack] Gadgets detected! they are at: ";
	            for(int i=1; i <= S_LENGTH; ++i){
					cerr << hex << "0x" << addresses[i] << ", ";
				}
				cerr << endl;
				kill();
	        }//if s_count >= slength, ROP detected
	    }
	}	
}

// count the number of call ins
VOID c_counter(ADDRINT ip, ADDRINT target, ADDRINT next){
	if(THR_DECT){
		if(STK_Search(symbols_libc, target) || STK_Search(symbols, target)){
			g_counter();
		}else{ // invaild call
			logic(ip);
		}
	}
	if( CRB_DECT ){
		if( next < execHigh && next > execLow ){
			c_count++;
		} 
		if( libcAcc && next < libcHigh && next > libcLow ){
			c_count++;
		}
	}
	if( STK_DECT && (next < execHigh && next > execLow) ){
		if(STK_Search(symbols, target)){
			if(libcAcc && target < libcHigh && target > libcLow && libcAcc){
				return ; // do not trace call inside of function@libc
			}
			if(STK_DECT){
				STK_Push(lstack ,next);
				// if(DEBUG) {
				// 	cerr << "Pushed: 0x" << std::hex << next << endl;
				// 	STK_Show(lstack);
				// }
			}
			// if(DEBUG){
			// 	cerr << "call[" << std::dec << c_count  << "] @ 0x"<< std::hex << ip << endl;
			// 	cerr << "call for 0x" << target << endl;
			// 	cerr << "next: 0x" << std::hex << next << endl;
			// }
		}
	}
	if( CPR_DECT ){
		STK_Push(cpra, next);
	}
	if( beAttacked ){
		if ( libcAcc && STK_Search(symbols_libc, target) ){
			string func = STK_QueryNameByAddr(symbols_libc, target);
			cerr << "[attack] Call2libc attack detected! call " << func;
			cerr << " addr: 0x" << std::hex << target << endl;
			kill();
		}else{
			cerr << "[attack] COP attack detected! gadget addr: 0x" << std::hex << target << endl;
			kill();
		}
	}
}

// count the number of ret ins
VOID r_counter(ADDRINT ip, ADDRINT target){
	if( R2L_DECT && libcAcc && STK_Search(symbols_libc, target) ){
		beAttacked = 1;
	}
	if( THR_DECT ){
		logic(ip);
	}
	if( CRB_DECT ){
	 	if (target < execHigh && target > execLow ){
			r_count++;
	 	}
	 	if (libcAcc && target < libcHigh && target > libcLow) {
			r_count++;
	 	}
	}
	if( STK_DECT && (target < execHigh && target > execLow) ){
		if(STK_Pop(lstack) != target){
			beAttacked = 1;
		}
	}
	if( CPR_DECT ){
		if(! STK_Search(cpra, target)){
			beAttacked = 1;
		}
	}
	if( beAttacked && libcAcc ){
		if (STK_Search(symbols_libc, target)){
			string func = STK_QueryNameByAddr(symbols_libc, target);
			cerr << "[attack] Return-into-libc attack detected! return to " << func;
			cerr << " addr: 0x" << std::hex << target << endl;
			kill();
		}else{
			cerr << "[attack] ROP attack detected! gadget addr: 0x" << std::hex << target << endl;
			kill();
		}
	}
}

// count the number of branch ins
VOID b_check(ADDRINT ip, ADDRINT target){
	if( GOT_DECT && STK_Search(symbols, ip) && libcAcc ){
		// got can be modified only 1 time
		if(target < execHigh && target > execLow){
			if( target != ip + 6){
				cerr << "[GOT] GOT overwrite dect!!!" << endl;
				// plt[0] first jmp must be plt[1] 
				beAttacked = 1; 
			}
			// cerr << "branch @ 0x" << hex << ip << " -> 0x" << next << endl;
		}
		else{ // plt[0] second jmp must be libc func with same name 
			string a = STK_QueryNameByAddr(symbols_libc, target);
			string b = STK_QueryNameByAddr(symbols, ip);
			if( b == a+"@plt"){
				// compare symbols name 
			}
			else{
				beAttacked = 1;
				cerr << "[GOT] GOT overwrite dect!!!" << endl;
				kill();
			}
		}
	}
	if( THR_DECT ){
		g_counter();
	}
	if( beAttacked ){
		cerr << "[attack] JOP attack detected! gadget addr: 0x" << std::hex << target << endl;
		kill();
	}
}

INT32 check(INS ins){
	return(INS_IsRet(ins) | INS_IsCall(ins) << 1 | INS_IsBranch(ins) << 2);
}

VOID Instruction(INS ins, VOID *v) {
	int flag = check(ins);
	if(flag & CALL){
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)c_counter, 
			IARG_INST_PTR, 
			IARG_BRANCH_TARGET_ADDR, 
			IARG_ADDRINT, INS_NextAddress(ins),
			IARG_END);
	}
	if(flag & RET){
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_counter, 
			IARG_INST_PTR, 
			IARG_BRANCH_TARGET_ADDR, 
			IARG_END);
	}
	if(flag & BRANCH){
		INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)b_check, 
			IARG_INST_PTR, 
			IARG_BRANCH_TARGET_ADDR, 
			IARG_END);
	}else{
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)g_counter, IARG_BRANCH_TARGET_ADDR, IARG_END);		
	}
	if( r_count > c_count ){
		beAttacked = 1;
		cerr << "[CRB] balance break! Count of RET is " << dec << r_count-c_count << " more than CALL !"<< endl;
	}
}

/* ===================================================================== */

VOID Fini(INT32 code, VOID *v) {
    cerr <<  "===============================================" << endl;
    cerr <<  "                MyPinTool done.                " << endl;
    cerr <<  "===============================================" << endl;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[]) {
	lstack = new(LinkStack);
	symbols = new(LinkStack);
	symbols_libc = new(LinkStack);
	cpra = new(LinkStack);
	STK_Init(lstack);		
	STK_Init(symbols);		
	STK_Init(symbols_libc);
	STK_Init(cpra);

	PIN_InitSymbols();

	if( PIN_Init(argc,argv) ) {
		return Usage();
	}

	// Register ImageLoad to be called when an image is loaded
	IMG_AddInstrumentFunction(ImageLoad, 0);

	// Register ImageUnload to be called when an image is unloaded
    IMG_AddUnloadFunction(ImageUnload, 0);

	INS_AddInstrumentFunction(Instruction, 0);

	PIN_AddFiniFunction(Fini, 0);
    

    cerr <<  "===============================================" << endl;
    cerr <<  "   current time : " << time() << "  "  << endl;
    cerr <<  " This application is instrumented by MyPinTool" << endl;
    cerr <<  "===============================================" << endl;
                                read_opt();
    cerr <<  "===============================================" << endl;

	// Never returns
	PIN_StartProgram();

	return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
