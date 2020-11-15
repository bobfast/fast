

using namespace System;


#include "Form1.h"

using namespace System::Windows::Forms;


//////////////////////////////////////////////////////////////////////////////
//Running Winform's Form1 instance.
[STAThread]
int main() {
	Application::EnableVisualStyles();
	Application::SetCompatibleTextRenderingDefault(false);
	Application::Run(gcnew CppCLRWinformsProjekt::Form1()); 
	return 0;
}