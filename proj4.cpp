#include "pin.H"
#include <map>
#include <iostream>

#define MAIN "main"
#define FILENO "fileno"

// Taint the memory if the source of input is stdin
#define FGETS "fgets"
#define GETS "gets"

// Propagate if the src is tainted
#define STRCPY "strcpy@plt"
#define STRNCPY "strncpy@plt"
#define STRCAT "strcat@plt"
#define STRNCAT "strncat@plt"
#define MEMCPY "memcpy@plt"

// Reset tainted memory
#define BZERO "bzero@plt"
#define MEMSET "memset@plt"

// map declaration
map <ADDRINT, bool> adrMap;


typedef int ( *FP_FILENO )(FILE*);
FP_FILENO org_fileno;

INT32 Usage()
{
                return -1;
}

bool isStdin(FILE *fd)
{
                int ret = org_fileno(fd);
                if(ret == 0) return true;
                return false;
}

bool fgets_stdin = false;
VOID fgetsTail(char* ret)
{
        //cout << "error in fgets tail" << endl;
        if(fgets_stdin) {
                //printf("fgetsTail: ret %p\n", ret);
                int strSize = strlen(ret);
                for(int i = 0; i < strSize; ++i){
                        unsigned int d = (unsigned int)&ret[i];
                        //cout << "fgetstail tainting byte. mem contains " << ret[i] << " at address " << hex << d << endl;
                        adrMap[d] = true;
                }

        }
        fgets_stdin = false;

}

VOID fgetsHead(char* dest, int size, FILE *stream)
{
                //cout << "error in fgetshead" << endl;
                if(isStdin(stream)) {
                                //printf("fgetsHead: dest %p, size %d, stream: stdin)\n", dest, size);
                                fgets_stdin = true;
                }
}


VOID getsTail(char* ret)
{
        //cout << "error in getsTail" << endl;
        int strSize = strlen(ret);
        for(int i = 0; i < strSize; ++i){
                unsigned int d = (unsigned int)&ret[i];
                //cout << "getstail tainting byte at " << hex << d << endl;
                adrMap[d] = true;
        }

}

VOID getsHead()
{
        //cout << "error in getsHead" << endl;
}

VOID mainHead(int argc, char* argv[], unsigned int* argvAdr)
{
        //cout << "argv addrress: " << hex << *argvAdr << endl;
        //cout << "in main. argc is " << argc << endl;
        //cout << "argv[0] length " << strlen(argv[0]) << endl;
        for(int i = 1; i < argc; i++){
                unsigned int d = (unsigned int)argv[i];
                //cout << "value from argv: " << argv[i] << endl;
                int strSize = strlen(argv[i]);
                //unsigned int d = (unsigned int)*argvAdr;
                for(int j = 0; j < strSize; ++j){
                        adrMap[d+j] = true;
                        //cout << "main tainting: " << *((unsigned char*)(d+j)) << "at "  << hex << d+j << endl;
                }
                //cout << " next arg" << endl;
        }
}

VOID mainTail()
{

}

VOID strcpyHead(char* dst, char* src)
{
        int strSize = strlen(src);
        for(int i = 0; i < strSize; ++i){
                unsigned int s = (unsigned int)&src[i];
                if(adrMap[s] == true){
                        //cout << "attempted copy on tainted byte at 0x" << hex << s << endl;
                        unsigned int d = (unsigned int)&dst[i];
                        adrMap[d] = true;
                        //cout << "strcpyhead tainting byte containing " << src[i]<< " at 0x" << hex << d << endl;
                }
        }
        //cout << "error inside strcpyHead " << endl;
}

VOID strcpyTail(char* str)
{
        //cout << "error inside strcpyTail " << endl;
}

VOID strncpyHead(char* dst, char* src, int size)
{
        //cout << "error inside strncpyHead " << endl;
        int strSize = strlen(src);
        for(int i = 0; i < strSize; ++i){
                unsigned int s = (unsigned int)&src[i];
                if(adrMap[s] == true){
                        //cout << "attempted copy on tainted byte at 0x" << hex << s << endl;
                        unsigned int d = (unsigned int)&dst[i];
                        adrMap[d] = true;
                        //cout << "tainting byte at 0x" << hex << d << endl;
                }
        }
}

VOID strncpyTail(char* dst)
{
        //cout << "error inside strncpyTail " << endl;
}

VOID strcatHead(char* dst, char* src)
{
        //cout << "error inside strcatHead " << endl;

        int strSize = strlen(src);
        int dstSize = strlen(dst);
        for(int i = 0; i < strSize; ++i){
                unsigned int s = (unsigned int)&src[i];
                if(adrMap[s] == true){
                        //cout << "attempted concat of tainted byte at " << hex << s << endl;
                        unsigned int d = (unsigned int)&dst[i+dstSize];
                        adrMap[d] = true;
                        //cout << "tainting byte at 0x" << hex << d << endl;
                }
        }
}

VOID strcatTail(char* dst)
{
        //cout << "error inside strcatTail " << endl;
}

VOID strncatHead(char* dst, char* src, int size)
{
        //cout << "error inside strncatHead " << endl;
}

VOID strncatTail(char* dst)
{
        //cout << "error inside strncatTail " << endl;
}

VOID memcpyHead(char* dst, char* src, size_t size)
{
        //cout << "error inside memcpyHead " << endl;

        for(unsigned int i = 0; i < size; ++i){
                unsigned int s = (unsigned int)&src[i];
                if(adrMap[s] == true){
                        unsigned int d = (unsigned int)&dst[i];
                        //cout << "tainted byte detected, copying from " << hex << s << endl;
                        adrMap[d] = true;
                }
        }
}

VOID memcpyTail(char* dst)
{
        //cout << "error inside memcpyTail " << endl;
}

VOID retcheck(unsigned int* targetAdr, unsigned int target)
{
        //unsigned int* targetAdr = &target;
        //cout << "checking ret to " << hex << target << endl << targetAdr << endl;
        if(adrMap[target] == true || adrMap[*targetAdr] == true){
                cout << "----------" << endl << "Attack Detected. Exiting." << endl;
                cout << "Attempted return to adress stored in tainted byte at 0x" << hex << target << endl;
                cout << "----------" << endl;
                exit(1);
        }
}

VOID bcheck(unsigned int* targetAdr, unsigned int target)
{
        //cout << "checking branch to " << hex << target << endl;
        //unsigned int* targetAdr = &target;
        if(adrMap[target] == true || adrMap[*targetAdr] == true){
                cout << "----------" << endl << "Attack Detected. Exiting." << endl;
                cout << "Attempted branch to adress stored in tainted byte at 0x" << hex << target << endl;
                cout << "----------" << endl;
                exit(1);
        }

}

VOID Instruction(INS ins, VOID *v)
{
        bool isret = LEVEL_CORE::INS_IsRet(ins);
        bool isbranch = LEVEL_CORE::INS_IsBranchOrCall(ins);

        if(isret){
                //cout << "isret called" << endl;
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)retcheck, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0, IARG_BRANCH_TARGET_ADDR, IARG_END);
        }
        else if(isbranch){
                //cout << "isbranch called" << endl;
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)bcheck, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0 , IARG_BRANCH_TARGET_ADDR, IARG_END);
        }

}

VOID Image(IMG img, VOID *v) {
                RTN rtn;

                //fgets
                rtn = RTN_FindByName(img, FGETS);
                if(RTN_Valid(rtn)) {
                                RTN_Open(rtn);
                                RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)fgetsHead,
                                                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                                        IARG_END);

                                RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)fgetsTail,
                                                                IARG_FUNCRET_EXITPOINT_VALUE,
                                                                IARG_END);
                                RTN_Close(rtn);
                }//fgets


                //gets
                rtn = RTN_FindByName(img, GETS);
                if(RTN_Valid(rtn)) {
                                RTN_Open(rtn);
                                RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)getsHead,
                                                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                                                IARG_END);

                                RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)getsTail,
                                                                IARG_FUNCRET_EXITPOINT_VALUE,
                                                                IARG_END);
                                RTN_Close(rtn);
                }//gets


                //main
                rtn = RTN_FindByName(img, MAIN);
                if(RTN_Valid(rtn)) {
                                RTN_Open(rtn);
                                RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)mainHead,
                                                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                                                IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
                                                                IARG_END);

                                RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)mainTail,
                                                                IARG_FUNCRET_EXITPOINT_VALUE,
                                                                IARG_END);

                                RTN_Close(rtn);
                }//main



                //strcpy
                rtn = RTN_FindByName(img, STRCPY);
                if(RTN_Valid(rtn)) {
                                RTN_Open(rtn);
                                RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strcpyHead,
                                                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                                                IARG_END);

                                RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)strcpyTail,
                                                                IARG_FUNCRET_EXITPOINT_VALUE,
                                                                IARG_END);

                                RTN_Close(rtn);
                }//strcpy


                //strncpy
                rtn = RTN_FindByName(img, STRNCPY);
                if(RTN_Valid(rtn)) {
                                RTN_Open(rtn);
                                RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strncpyHead,
                                                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                                                IARG_END);

                                RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)strncpyTail,
                                                                IARG_FUNCRET_EXITPOINT_VALUE,
                                                                IARG_END);

                                RTN_Close(rtn);
                }//strncpy


                //strcat
                rtn = RTN_FindByName(img, STRCAT);
                if(RTN_Valid(rtn)) {
                                RTN_Open(rtn);
                                RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strcatHead,
                                                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                                                IARG_END);

                                RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)strcatTail,
                                                                IARG_FUNCRET_EXITPOINT_VALUE,
                                                                IARG_END);

                                RTN_Close(rtn);
                }//strcat


                //strncat
                rtn = RTN_FindByName(img, STRNCAT);
                if(RTN_Valid(rtn)) {
                                RTN_Open(rtn);
                                RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strncatHead,
                                                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                                                IARG_END);

                                RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)strncatTail,
                                                                IARG_FUNCRET_EXITPOINT_VALUE,
                                                                IARG_END);
                                RTN_Close(rtn);
                }//strncat


                //memcpy
                rtn = RTN_FindByName(img, MEMCPY);
                if(RTN_Valid(rtn)) {
                                RTN_Open(rtn);
                                RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)memcpyHead,
                                                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                                                IARG_END);

                                RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)memcpyTail,
                                                                IARG_FUNCRET_EXITPOINT_VALUE,
                                                                IARG_END);

                                RTN_Close(rtn);
                }//memcpy



                rtn = RTN_FindByName(img, FILENO);
                if(RTN_Valid(rtn)) {
                                RTN_Open(rtn);
                                AFUNPTR fptr = RTN_Funptr(rtn);
                                org_fileno = (FP_FILENO)(fptr);
                                RTN_Close(rtn);
                }
}


int main(int argc, char *argv[])
{
  PIN_InitSymbols();

                if(PIN_Init(argc, argv)){
                                return Usage();
                }

  IMG_AddInstrumentFunction(Image, 0);
                INS_AddInstrumentFunction(Instruction, 0);
                PIN_StartProgram();

                return 0;
}
