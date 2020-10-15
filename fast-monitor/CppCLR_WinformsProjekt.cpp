#include "pch.h"

using namespace System;

//int main(array<System::String ^> ^args)
//{
//    return 0;
//}

#include "Form1.h"


using namespace System::Windows::Forms;



[STAThread]
int main() {
	Application::EnableVisualStyles();
	Application::SetCompatibleTextRenderingDefault(false);
	//CppCLRWinformsProjekt::Form1^ f1;
	//Application::Run(f1 = gcnew CppCLRWinformsProjekt::Form1()); 
	CppCLRWinformsProjekt::Form1^ f1 = gcnew CppCLRWinformsProjekt::Form1();

	Application::Run(f1);

	return 0;
}