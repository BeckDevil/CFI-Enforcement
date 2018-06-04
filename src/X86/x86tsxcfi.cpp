#include "X86.h"
#include "X86Subtarget.h"
#include "X86InstrBuilder.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineregisterInfo.h"
#include "llvm/Support/raw_ostream.h"
#include "string.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/ToolOutputFile.h"

using namespace llvm;

// Command line options
// One specifies the mode 
// Another specifies if we are building statically
static cl::opt<std::string> TsxCfiMode("tsx-cfi", cl::desc("Tsx CFI Mode"),
		cl::value_desc("Mode of operation: rtm or hle"), cl::init(""));
static cl::opt<bool>TsxCfiStatic("tsx-cfi-static", cl::Hidden, cl::desc("Disable nop emits for static linking"),
		cl::init(false));

// RTM Mode
#define NEEDS_XBEGIN 0x0001
#define NEEDS_XEND 0x0002
#define DIRECT_CALL 0x0004
#define INDIRECT_CALL_REG 0x0008
#define INDIRECT_CALL_MEM 0x0010
#define TAIL_CALL_REG 0x0020
#define TAIL_CALL_MEM 0x0040
#define IS_RET 0x0080

// HLE
#define NEEDS_XACQUIRE NEEDS_XBEGIN
#define NEEDS_XRELEASE NEEDS_XEND

// Utility functions
int getOpcodeProp(unsigned int Opcode)
{
	switch(Opcode){
		case X86::CALL64r:
			return NEEDS_XBEGIN | NEEDS_XEND | INDIRECT_CALL_REG;
		case X86::CALL64m:
			return NEEDS_XBEGIN | NEEDS_XEND | INDIRECT_CALL_MEM;
		
		case X86::CALLpcre116:
		case X86::CALLpcrel32:
		case X86::CALL64pcrel32:
			return NEEDS_XEND | DIRECT_CALL;

		case X86::RETL:
		case X86::RETQ:
		case X86::RETW:
			return NEEDS_XBEGIN | IS_RET;
		
		case X86::TAILJMPr64:
			return NEEDS_XBEGIN | TAIL_CALL_REG;
		case X86::TAILJMPm64:
			return NEEDS_XBEGIN | TAIL_CALL_MEM;
		case X86::TAILJMPd64:
			return DIRECT_CALL;
		default:
			return 0;
	}
}

void emitNop(MachineInstr *MI, MachineBasicBlock *MBB, int count)
{
	MachineInstrBuilder MIB;
	const TargetInstrInfo* TII = MBB->getParent()->getSubtarget().getInstrInfo();
	while(count > 0){
		MIB = BuildMI(*MBB, MI, MI->getDebugLoc(), TII->get(X86::NOOP));
		count--;
	}
}

bool contains(std::vector<llvm::MachineInstr*> v, MachineInstr* mbb)
{
	return std::find(std::begin(v), std::end(v), mbb) != std::end(v);
}

MachineBasicBlock* createMBBandInsertAfter(MachineBasicBlock *InsertPoint)
{
	MachineFunctionPass *MF = InsertPoint->getParent();
	MachineBasicBlock *newMBB = MF->CreateMachineBasicBlock();
	MF->insert(InsertPoint->getIterator(), newMBB);
	newMBB->moveAfter(InsertPoint);
	InsertPoint->addSuccessor(newMBB);
	newMBB->transferSuccessorsAndUpdatePHIs(InsertPoint);
	return newMBB;
}

const char *RegisterToString(unsigned int Reg)
{
	switch(Reg)
	{
		case X86::RAX:
			return "rax";
		case X86::RBX:
			return "rbx";
		case X86::RCX:
			return "rcx";
		case X86::RDX:
			return "rdx";
		case X86::RSI:
			return "rsi";
		case X86::RDI:
			return "rdi";
		case X86::RBP:
			return "rbp";
		case X86::RSP:
			return "rsp";
		case X86::R8:
			return "r8";
		case X86::R9:
			return "r9";
		case X86::R12:
			return "r12";
		case X86::R13:
			return "r13";
		case X86::R14:
			return "r14";
		case X86::R15:
			return "r15";
		default:
			assert(false && "Can not convert register to stringi.");
			return 0;
	}
}

namespace
{
	class TsxCfiRTM : public MachineFunctionPass
	{
		public:
			TsxCfiRTM(): MachineFunctionPass(ID){}
			bool runOnMachineFunction(MachineFunction &MF) override;
			const char* getPassName() const override{return "Tsx Control Flow Integrity with Restricted Transactional Memory";}
			static char ID;
		private:
			MachineBasicBlock* createFallbackMemBlock(MachineInstr *MI, MachineBasicBlock *jmpTargetMBB, MachineBasicBlock *callTargetMBB);
			void insertXBegin(MachineInstr *MI, MachineBasicBlock *MBB);
			void insertXEnd(MachineInstr *MI, MachineBasicBlock *MBB);
			const TargetInstrInfo *TII;
	};
	char TsxCfiRTM::ID = 0;
}

FunctionPass* llvm::createTsxCfiRTM()
{
	return new TsxCfiRTM();
}

MachineBasicBlock* TsxCfiRTM::createFallbackMemBlock(MachineInstr* MI, MachineBasicBlock* jmpTargetMBB, MachineBasicBlock* callTargetMBB)
{
	// Initializations
	MachineBasicBlock* MBB = MI->getParent();
	MachineFunction* MF = MBB->getParent();
	MachineInstrBuilder MIB;
	MachineBasicBlock* newMBB = createMBBandInsertAfter(&8std::prev(MF->end()));
	MachineBasicBlock* gotMBB = createMBBandInsertAfter(newMBB);
	MachineBasicBlock* validMBB = createMBBandInsertAfter(gotMBB);
	MachineBasicBlock* anotherMBB = createMBBandInsertAfter(validMBB);
	DebugLoc DL = MI->getDebugLoc();
	newMBB->addSuccessor(jmpTargetMBB);
	newMBB->addSuccessor(gotMBB);
	gotMBB->addSuccessor(validMBB);
	validMBB->addSuccessor(anotherMBB);
	MachineInstr* castMIB;
	MachineInstr* FirstInst = newMBB->begin();

	// PUSH R10, restore RAX
	MIB = BuildMI(*newMBB, FirstInst, DL, TII->get(X86::PUSH64r), X86::R10);
	MIB = BuildMI(*newMBB, FIrstInst, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R11);

	// MOV RAX, target
	MIB = BuildMI(*newMBB, FirstInst, DL, TII->get(X86::MOV64rm), X86::RAX);
	for(const MachineOperand &MO : MI->operands()){
		// copy all the operands
		MIB.addOperand(MO);
	}

	castMIB = MIB;
	if(castMIB->getOperand(1).getReg() == X86::RSP)
		castMIB->getOperand(4).setImm(castMIB->getOperand(4).getImm()+8);

	// MOV RAX [RAX]
	MIB = BuildMI(*newMBB, FirstInst, DL, TII->get(X86::MOV64rm), X86::RAX);
	addRegOffset(MIB, X86::RAX, false, 0);

	// AND RAX, 0xffffff
	MIB = BuildMI(*newMBB, FirstInst, DL, TII->get(X86::AND64ri32), X86::RAX).addImm(0xffffff);

	// CMP RAX, 0xd5010f
	MIB = BuildMI(*newMBB, FirstInst, DL, TII->get(X86::CMP64ri32), X86::RAX).addImm(0xd5010f);

	// JNE next_check
	MIB = BuildMI(*newMBB, FirstInst, DL, TII->get(X86::JNE_1)).addMBB(gotMBB);

	// restore RAX
	MIB = BuildMI(*newMBB, FirstInst, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R11);
	// mov r11, target
	MIB = BuildMI(*newMBB, FirstInst, DL, TII->get(X86::MOV64rm), X86::R11);
	for(const MachineOperand &MO : MI->operands()){
		// copy all the operands
		MIB.addOperand(MO);
	}

	castMIB = MIB;
	if(castMIB->getOperand(1).getReg()==X86::RSP)
		castMIB->getOperand(4).setImm(castMIB->getOperand(4).getImm()+8);

	// ADD R11,3 and  JMP target
	MIB = BuildMI(*newMBB, FirstInst, DL, TII->get(X86::ADD64ri8), X86::R11).addReg(X86::R11).addImm(3);
	MIB = BuildMI(*newMBB, FirstInst, DL, TiI->get(X86::JMP64r)).addReg(X86::R11);

	// Check if got unresolved
	FirstInst = gotMBB->begin();

	MIB = BuildMI(*gotMBB, FirstInst, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R11);
	MIB = BuildMI(*gotMBB, FirstInst, DL, TII->get(X86::MOV64rm), X86::RAX);
	for(const MachineOperand &MO : MI->operands()){
		MIB.addOperand(MO);
	}

	castMIB = MIB;
	if(castMIB->getOperand(1).getReg()==X86::RSP)
		castMIB->getOperand(4).setImm(castMIB->getOperand(4).getImm()+8);

	MIB = BuildMI(*gotMBB, FirstInst, DL, TII->get(X86::MOV64rr), X86::R10).addReg(X86::RAX);
	MIB = BuildMI(*gotMBB, FirstInst, DL, TII->get(X86::ADD64ri32), X86::R10).addReg(X86::R10).addImm(6);
	MIB = BuildMI(*gotMBB, FirstInst, DL, TII->get(X86::MOV32rm), X86::EAX);
	addRegOffset(MIB, X86::RAX, false, 2);
	MIB = BuildMI(*gotMBB, FirstInst, DL, TII->get(X86::ADD64rr), X86::RAX).addReg(X86::RAX).addReg(X86::R10);
	MIB = BuildMI(*gotMBB, FirstInst, DL, TII->get(X86::MOV64rm), X86::EAX);
	addRegOffset(MIB, X86::RAX, false, 0);

	MIB = BuildMI(*gotMBB, FirstInst, DL, TII->get(X86::CMP64rr), X86::RAX).addReg(X86::R10);
	// jne next_check
	MIB = BuildMI(*gotMBB, FirstInst, DL, TII->get(X86::JNE_1)).addMBB(validMBB);

	// Otherwise jump
	// Restore RAX
	MIB = BuildMI(*gotMBB, FirstInst, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R11);
	MIB = BuildMI(*gotMBB, FirstInst, DL, TII->get(X86::JMP64m));
	for(const MachineOperand &MO : MI->operands()){
		MIB.addOperand(MO);
	}

	// Valid MBB
	FirstInst = validMBB->begin();
	// Save RAX in r10 (now rax points to the resolved function)
	MIB = BuildMI(*validMBB, FirstInst, DL, TII->get(X86::MOV64rr), X86::R10).addReg(X86::RAX);

	// ## Check if got resolved ## 
	MIB = BuildMI(*validMBB, FirstInst, DL, TII->get(X86::MOV64rm), X86::RAX);
	if(TsxCfiStatic){
		// if RELRO we check the resolved function -3 points to xend
		// add r11, 3
		addRegOffset(MIB, X86::RAX, false, -3);
	}
	else{
		addRegOffset(MIB, X86::RAX, false, 0);
	}

	// and rax, 0xffffff
	MIB = BuildMI(*validMBB, FirstInst, DL, TII->get(X86::AND64ri32), X86::RAX).addImm(0xffffff);
	MIB = BuildMI(*validMBB, FirstInst, DL, TII->get(X86::CMP64ri32), X86::RAX).addImm(0xd5010f);

	// jne violation
    MIB = BuildMI(*validMBB, FirstInst, DL, TII->get(X86::JNE_1)).addExternalSymbol("__tsx_cfi_violation");
	
	// Restore RAX
    MIB = BuildMI(*validMBB, FirstInst, DL, TII->get(X86::MOV64rr), X86::RAX).addReg(X86::R11);

    // mov r11, target
    MIB = BuildMI(*validMBB, FirstInst, DL, TII->get(X86::MOV64rr), X86::R11).addReg(X86::R10);
	if(!TsxCfiStatic){ 
		// if not RELRO we add 3 so we skip the xend
		// add r11, 3
		MIB = BuildMI(*validMBB, FirstInst, DL, TII->get(X86::ADD64ri8), X86::R11).addReg(X86::R11).addImm(3);
	}
	// jmp target
	MIB = BuildMI(*validMBB, FirstInst, DL, TII->get(X86::JMP64r)).addReg(X86::R11);
	return newMBB;
}

void TsxCfiRTM::insertXBegin(MachineInstr* MI, MachineBasicBlock *MBB)
{
	MachineFunction* MF = MBB->getParent();
	MachineInstrBuilder MIB;
	char symbol[50] = {0};
	MachineBasicBlock *fbMBB;
	int RetValReg = X86::R11; // Where to save eax
	int RipReg = X86::R10; // Where we put out the return IP
	int prop = getOpcodeProp(MI->getOpcode());
	DebugLoc DL = MI->getDebugLoc();

	MIB = BuildMI(*MBB, MI, DL, TII->get(X86::MOV64rr), RetValReg).addReg(X86::RAX);

	if(prop & IS_RET){
		strcpy(symbol, "__tsx_cfi_fb_rtm_ret");
	}
	else if(prop & INDIRECT_CALL_REG){
		strcpy(symbol, "__tsx_cfi_fb_rtm_call_");
		strcat(symbol, RegisterToString(MI->getOperand(0).getReg()));
	}
	else if(prop & TAIL_CALL_REG){
		strcpy(symbol, "__tsx__cfi_fb_rtm_jmp_");
		strcat(symbol, RegisterToString(MI->getOperand(0).getReg()));
	}
	else if(Prop & (INDIRECT_CALL_MEM | TAIL_CALL_MEM)){
		int FirstReg = MI->getOperand(0).getReg();
		int SecondReg = MI->getOperand(2).getReg();

		assert(FirstReg != X86::R11 && SecondReg != X86::R11 && "Crap, Indirect call with R10 or R11!!");

		// Splice MBB where the call is. SO the callMBB can be the target of the fallback Path
		MachineBasicBlock* callMBB = MF->CreateMachineBasicBlock();
		MF->insert(MBB->getIterator(), callMBB);
		callMBB->moveAfter(MBB);
		MBB->addSuccessor(callMBB);
		callMBB->splice(callMBB->begin(), MBB, MI, MBB->end());

		MachineBasicBlock* newMBB = MF->CreateMachineBasicBlock();
		MF->insert(callMBB->getIterator(), newMBB);
		callMBB->moveAfter(newMBB);
		newMBB->addSuccessor(callMBB);

		// The newly created newMBB will reside between callMBB and MBB 
		// This is the point where the fallback path starts
		fbMBB = createFallbackMemBlock(MI, newMBB, callMBB);
		MBB = newMBB;
		MI = MBB->begin();
	}

	// LEA RipReg, [%RIP]0
	if(prop & (INDIRECT_CALL_REG | INDIRECT_CALL_MEM)){
		MIB = BuildMI(*MBB, MI, DL, TII->get(X86::LEA64r), RipReg);
		addRegOffset(MIB, X86::RIP, false, 0);
	}

	MIB = BuildMI(*MBB, MI, DL, TII->get(X86::XBEGIN_4));
	if(strcmp(symbol, "") != 0){
		char* dupsymbol = strdup(symbol);
		MIB.addExternalSymbol(dupsymbol);
	}
	else{
		MIB.addMBB(fbMBB);
	}
}

void TsxCfiRTM::insertXEnd(MachineInstr* MI, MachineBasicBlock* MBB)
{
	MachineInstrBuilder MIB;
	MIB = BuildMI(*MBB, MI, MBB->begin()->getDebugLoc(), TII->get(X86::XEND));
}

bool TsxCfiRTM::runOnMachineFunction(MachineFunction &MF)
{
	MachineFunction::iterator MBB, MBBE;
	MachineBasicBlock::iterator MBBI, MBBIE;
	MachineInstr *MI;
	int OpcodeProp;
	TII = MF.getSubtarget().getInstrInfo();
	MachineInstrBuilder MIB;

	MachineBasicBlock* FirstBB = (MachineBasicBlock*)MF.begin();

	// Skip empty MBBs
	if(strcmp(MF.getName().str().c_str(), "dummy") == 0){
		errs() << "Not instrumenting dummy!\n";
		return false;
	}

	//Instrumenting the entry point of every function with XEND
	MachineInstr* FirstInstr = (MachineInstr*)FirstBB->begin();
	insertXEnd(FirstInstr, FirstBB);

	for(MBB = MF.begin(), MBBE = MF.end(); MBB != MBBE; ++MBB){
		for(MBBI = MBB.begin(), MBBIE = MBB.end(); MBBI != MBBIE; ++MBBI){
			MI = MBBI;
			OpcodeProp = getOpcodeProp(MI->getOpcode());

			if(OpcodeProp & NEEDS_XEND){
				insertXEnd(std::next(MBBI), &*MBB);
			}
			if(OpcodeProp & NEEDS_XBEGIN){
				insertXBegin(MBBI, &*MBB);
				MBB = MI->getParent()->getIterator();
				MBBIE = MBB->end();
				MBBE  = MF->end();
			}
			if(OpcodeProp & DIRECT_CALL){
				if(!TsxCfiStatic)
					emitNop(MI, &*MBB, 16); 
				MI->getOperand(0).setOffset(3);
			}
		}
	}
	return true;
}

namespace
{
	class TsxCfiHLE : public MachineFunctionPass
	{
		public:
			TsxCfiHLE() : MachineFunctionPass(ID){}
			bool runOnMachineFunction(MachineFunction &MF) override;
			const char *getPassName() const override{return "Tsx Control Flow Integrity with Hardware Lock Elision";}
			static char ID;
		private:
			MachineBasicBlock *createFallbackMemBlock(MachineInstr *MI, MachineBasicBlock *jmpTargetMBB)
			void insertXAcquire(MachineInstr* MI, MachineBasicBlock *MBB, int StackPointerOffset);
			void insertXRelease(MachineInstr* MI, MachineBasicBlock *MBB, int StackPointerOffset);
			const TargetInstrInfo *TII;
	};
	char TsxCfiHLE::ID = 0;
}

FunctionPass *llvm::createTsxCfiHLE()
{
	return new TsxCfiHLE();
}
MachineBasicBlock* TsxCfiHLE::createFallbackMemBlock(MachineInstr *MI, MachineBasicBlock *jmpTargetMBB)
{
	MachineBasicBlock *MBB = MI->getParent();
	MachineFunction *MF = MBB->getparent();
	MachineInstrBuilder MIB;
	MachineBasicBlock *newMBB = createMBBandInsertAfter(&*std::prev(MF->end()));
	MachineBasicBlock *gotMBB = createMBBandInsertAfter(newMBB);
	MachineBasicBlock *validMBB = createMBBandInsertAfter(gotMBB);
	DebugLoc DL = MI->getDebugLoc();

	newMBB->addSuccessor(jmpTargetMBB);
	newMBB->addSuccessor(gotMBB);
	gotMBB->addSuccessor(validMBB);

	MachineInstr *FirstInst = newMBB->begin();
	// R11 <- label, R10 scratch register
	// Load in the R11 what we expect to find at target site(xrelease label)
	MIB = BuildMI(*newMBB, FirstInst, DL, TII->get(X86::SHL64ri), X86::R11).addReg(X86::R11).addImm(0x20);
	MIB = BuildMI(*newMBB, FirstInst, DL, TII->get(X86::MOV32ri), X86::R10).addImm(0xf8246c81);
	MIB = BuildMI(*newMBB, FirstInst, DL, TII->get(X86::ADD64rr), X86::R11).addReg(X86::R11).addReg(x86::R10);

	//Move in R10, the target of the indirect transfer
	MIB = BuildMI(*newMBB, FirstInst, DL, TTI->get(X86::MOV64rm), X86::R10);
	for(const machineOperand &MO : MI->operands()){
		// Copy all the operands
		MIB.addOperand(MO);
	}

	// Dereference the target
	MIB = BuildMI(*newMBB, FirstInst, DL, TII->get(X86::MOV64rm), X86::R10);
	addRegOffset(MIB, X86::R10, false, 2);

	// Compare dereferenced target and expected target
	MIB = BuildMI(*newMBB, FirstInst, DL, TII->get(X86::CMP64rr), X86::R10).addReg(X86::R11);

	//jne gotMBB
	MIB = BuildMI(*newMBB, FirstInst, DL, TII->get(X86::JNE_1)).addMBB(gotMBB);

	//Otherwise it is a benign transfer, so jump back to the call instruction
	MIB = BuildMI(*newMBB, FirstInst, DL, TII->get(X86::JMP_1)).addMBB(jmpTargetMBB);
	FirstInst = gotMBB->begin();
	
	// Save RAX, Move in the RAX the target
	MIB = BuildMI(*gotMBB, FirstInst, DL, TII->get(X86::PUSH64r), X86::RAX);
	MIB = BuildMI(*gotMBB, FirstInst, DL, TII->get(X86::MOV64rm), X86::RAX);
	for(const MachineOperand &MO : MI->operands()){
		//Copy all the operands
		MIB.addOperand(MO)
	}

	// The control flow is performed by PLT and GOT
	// PLT --> Program Linkage Table
	// GOT --> Global Offset Table
	// Check if the entry is unresolved
	MIB = BuildMI(*gotMBB, FirstInst, DL, TII->get(X86::MOV64rr), X86::R10).addReg(X86::RAX);
	// Add +6 to R10, so that it points to the instruction after jmp in PLT
	MIB = BuildMI(*gotMBB, FirstInst, DL, TII->get(X86::ADD64ri32), X86::R10).addReg(X86::R10).addImm(6);
	MIB = BuildMI(*gotMBB, FirstInst, DL, TII->get(X86::MOV32rm), X86::EAX);
	addRegOffset(MIB, X86::RAX, false, 2);
	MIB = BuildMI(*gotMBB, FirstInst, DL, TII->get(X86::ADD64rr), X86::RAX).addReg(X86::RAX).addReg(X86::R10);

	// Now in RAX we have the address of the GOT entry
	MIB = BuildMI(*gotMBB, FirstInst, DL, TII->get(X86::MOV64rm), X86::EAX);
	addRegOffset(MIB, X86::RAX, false, 0);
	MIB = BuildMI(*gotMBB, FirstInst, DL, TII->get(X86::CMP64rr), X86::RAX).addReg(X86::R10);
	MIB = BuildMI(*gotMBB, FirstInst, DL, TII->get(X86::JE_1)).addMBB(validMBB);

	MIB = BuildMI(*gotMBB, FIrstInst, DL, TII->get(X86::MOV64rm), X86::RAX);
	if(TsxCfiStatic){
		addRegOffset(MIB, X86::RAX, false, -10+2);
	}
	else{
		addRegOffset(MIB, X86::RAX, false, 2);
	}

	// R11 == expected target
	MIB = BuildMI(*gotMBB, FirstInst, DL, TII->get(X86::CMP64rm), X86::RAX).addReg(X86::R11);
	
	// jne  means violation
	MIB = BuildMI(*gotMBB, FirstInst, DL, TII->get(X86::JNE_1)).addExternalSymbol("__tsx_cfi_violation");
	
	FirstInst = validMBB->begin();
	// Restore RAX
	MIB = BuildMI(*validMBB, FirstInst, DL, TII->get(X86::POP64r), X86::RAX);
	// Jump to the target
	MIB = BuildMI(*validMBB, FIrstInst, DL, TII->get(X86::JMP_1)).addMBB(jmpTargetMBB);

	return newMBB;
}

void TsxCfiHLE::insertXAcquire(MachineInstr* MI, MachineBasicBlock* MBB, int StackPointerOffset)
{
	MachineInstrBuilder MIB;
	MachineFunction *MF = MBB->getParent();
	DebugLoc DL;
	char symbol[50] = {0};
	MachineBasicBlock *fbMBB;
	uint32_t FakeLabel = 0x80808080;
	unsigned prop = getOpcodeProp(MI->getOpcode());
	int LabelReg = X86::R11; // save the label
	int RipReg = X86::R10; // return address

	MachineBasicBlock* newMBB = MF->CreateMachineBasicBlock();
	MachineBasicBlock* xtestMBB = MF->CreateMachineBasicBlock();
	MF->insert(MBB->getIterator(), newMBB);
	MF->insert(MBB->getIterator(), xtestMBB);

	newMBB->moveAfter(MBB);
	xtestMBB->moveAfter(MBB);

	MBB->addSuccessor(newMBB);
	MBB->addSuccessor(xtestMBB);
	MBB->splice(newMBB->begin(), MBB, MI, MBB->end());

	newMBB->transferSuccessorsAndUpdatePHIs(MBB);

	// XACQUIRE + XTEST +JE RET
	DL = MF->begin()->begin()->getDebugLoc();
	MIB = BuildMI(*MBB, MBB->end(), DL, TII->get(X86::XACQUIRE_PREFIX));
	MIB = BuildMI(*MBB, MBB->end(), DL, TII->get(X86::LOCK_PREFIX));
	MIB = BuildMI(*MBB, MBB->end(), DL, TII->get(X86::ADD32mi));
	addRegOffset(MIB, X86::RSP, false, StackPointerOffset);
	MIB.addImm(FakeLabel);
	MIB = BuildMI(*MBB, MBB->end(), DL, TII->get(X86::XTEST));
	MIB = BuildMI(*MBB, MBB->end(), DL, TII->get(X86::JNE_1)).addMBB(newMBB);

	MachineBasicBlock::iterator InsertPoint = xtestMBB->begin();
	MIB = BuildMI(*xtestMBB, InsertPoint, DL, TII->get(X86::MOV32ri), LabelReg).addImm(FakeLabel);

	if(prop & IS_RET)
		strcpy(symbol, "__tsx_cfi_fb_hle_ret");
	else if(prop & INDIRECT_CALL_REG){
		strcpy(symbol, "__tsx_cfi_fb_hle_call_");
		strcat(symbol, RegisterToString(MI->getOperand(0).getReg()));
		MIB = BuildMI(*xtestMBB, InsertPoint, DL, TII->get(X86::LEA64r), RipReg);
		addRegOffset(MIB, X86::RIP, false, 0);
	}
	else if(prop & TAIL_CALL_REG){
		strcpy(symbol, "__tsx_cfi_fb_hle_jmp_");
		strcat(symbol, RegisterToString(MI->getOperand(0).getReg()));
	}
	else if(prop &(INDIRECT_CALL_MEM | TAIL_CALL_MEM)){
		fbMBB = createFallbackMemBlock(MI, newMBB);
	}

	// JMP to the fallback path
	MIB = BuildMI(*xtestMBB, InsertPoint, DL, TII->get(X86::JMP_1));
	if(strcmp(symbol, "") != 0){
		char* dupsymbol = strdup(symbol);
		MIB.addExternalSymbol(dupsymbol);
	}
	else{
		assert(fbMBB != NULL && "HLE: adding an non allocated mbb?!");
		MIB.addMBB(fbMBB);
	}
}

// XRELEASE, release the tsx section lock
void TsxCfiHLE::insertXRelease(MachineInstr* MI, MachineBasicBlock* MBB, int StackPointerOffset)
{
	MachineInstrBuilder MIB;
	MIB = BuildMI(*MBB, MI, MBB->begin()->getDebugLoc(), TII->get(X86::XRELEASE_PREFIX));
	MIB = BuildMI(*MBB, MI, MBB->begin()->getDebugLoc(), TII->get(X86::LOCK_PREFIX));
	MIB = BuildMI(*MBB, MI, MBB->begin()->getDebugLoc(), TII->get(X86::SUB32mi));

	addRegOffset(MIB, X86::RSP, false, StackPointerOffset);
	MIB.addImm(0x80808080);
}

bool TsxCfiHLE::runOnMachineFunction(MachineFunction &MF)
{
	MachineFunction::iterator MBB, MBBE;
	MachineBasicBlock::iterator MBBI, MBBIE;
	MachineInstr* MI;
	int OpcodeProp;
	TII = MF.getSubtarget().getInstrInfo();
	MachineInstrBuilder MIB;

	MachineBasicBlock *FirstBB = (MachineBasicBlock*)MF.begin();
	std::vector<llvm::MachineInstr*> XAcquiredInstr;

	// Don't instrument the dummy
	if(strcmp(MF.getName().str().c_str(), "dummy") == 0){
		errs() << "Not instrumenting dummy!\n";
		return false;
	}

	// Skipping empty MBB
	while(FirstBB->empty()){
		FirstBB = std::next(FirstBB);
	}

	//get the first instruction in given basic block
	MachineInstr *FirstInstr = (MachineInstr*)FirstBB->begin();
	insertXRelease(FirstInstr, FirstBB, -8);

	// Every entry of machinefunction MF
	for(MBB = MF.begin(), MBBE = MF.end(); MBB != MBBE; ++MBB){
		for(MBBI = MBB->begin(), MBBIE = MBB->end(); MBBI != MBBIE; ++MBBI){
			MI = MBBI;
			if(contains(XAcquiredInstr, MI)){
				continue;
			}

			OpcodeProp = getOpcodeProp(MI->getOpcode());
			if(OpcodeProp & NEEDS_XRELEASE){
				insertXRelease(std::next(MBBI), &*MBB, -16);
			}
			if(OpcodeProp & NEEDS_XACQUIRE){
				XAcquiredInstr.push_back(MI);
				if(OpcodeProp & (IS_RET | TAIL_CALL_MEM | TAIL_CALL_REG))
					insertXAcquire(MBBI, &*MBB, -8);
				else
					insertXAcquire(MBBI, &*MBB, -16);
				break;
			}

			if(OpcodeProp & DIRECT_CALL){
				if(!TsxCfiStatic)
					emitNop(MI, &*MBB, 33);
				MI->getOperand(0).setOffset(10);
			}
		}
	}
	return true;
}

