#include "X86.h"
#include "X86Subtarget.h"
#include "X86InstrBuilder.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace
{
	class TsxRewriteCallReg : public MachineFunctionPass
	{
		public:
			TsxRewriteCallReg(): MachineFunctionPass(ID){}
			bool runOnMachineFunction(MachineFunction &MF) override;
			const char* getPassName() const override {return "TSX control Flow register Rewriting Pass";}
			static char ID;
	};
	char TsxRewriteCallReg::ID = 0;
}

FunctionPass *llvm::createTsxRewritieCallReg()
{
	return new TsxRewriteCallReg();
}

bool TsxRewriteCallReg::runOnMachineFunction(MachineFunction &MF)
{
	MachineFunction::iterator MBB, MBBE;
	MachineBasicBlock::iterator MBBI, MBBEI;
	std::vector<llvm::MachineInstr*> VirtregToRewrite;
	MachineRegisterInfo &MRI = MF.getRegInfo();
	const TargetRegisterInfo *TRI = MF.getSubtarget().getRegisterInfo();

	MachineInstr *MI;
	for(MBB = MF.begin(), MBBE = MF.end(); MBB != MBBE; ++MBB){
		for(MBBI = MBB.begin(), MBBEI = MBB->end(); MBBI != MBBEI; ++MBBI){
			MI = MBBI;
			if(MI->getOpcode() == X86::CALL64r || MI->getOpcode() == X86::CALL64m || 
					MI->getOpcode() == X86::TAILJMPr64 || MI->getOpcode() == X86::TAILJMPm64||
					MI->getOpcode() == X86::TailJMPr || MI->getOpcode() == X86TCRETURNri64){
				for(const MachineOperand &MO : MI->operands()){
					//Loop over all the operands
					if(MO.isReg() && TRI->isVirtualRegister(MO.getReg())){
						MRI.setRegClass(MO.getReg(), &X86::GR64_TSXRegClass);
					}
				
				}
			}	
		}
	}
	return true;
}
static RegisterPass<TsxRewriteCallReg> X("TsxRewriteCallRegpass", "TsxRewriteCallReg");

