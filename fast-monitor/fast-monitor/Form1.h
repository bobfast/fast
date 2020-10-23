#pragma once
#include <stdio.h>
#include <Windows.h>
#include "tchar.h"
#include <tlhelp32.h>
#include <detours.h>
#include <time.h>
#include <utility>
#include <string>
#include <vector>
#include <unordered_map>
#pragma warning(push)
#if _MSC_VER > 1400
#pragma warning(disable : 6102 6103) // /analyze warnings
#endif
#include <strsafe.h>
#pragma warning(pop)

void init();
int mon(int isFree_);
void exiting();

static FILE* pFile = NULL;
static std::unordered_map<std::string, std::vector<std::pair<DWORD64, DWORD>>> rwxList;

namespace CppCLRWinformsProjekt {

	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;

	/// <summary>
	/// Zusammenfassung f? Form1
	/// </summary>




	public ref class Form1 : public System::Windows::Forms::Form
	{
	public:
		Form1(void)
		{
			InitializeComponent();
			init();
			//
			//TODO: Konstruktorcode hier hinzuf?en.
			//
		}

	protected:
		/// <summary>
		/// Verwendete Ressourcen bereinigen.
		/// </summary>
		~Form1()
		{
			exiting();
			if (components)
			{
				delete components;
			}
		}
	private: System::Windows::Forms::Button^ hookAndMonitoring;
	private: System::Windows::Forms::Button^ unhook;
	private: System::Windows::Forms::TextBox^ logBox;
	private: System::Windows::Forms::CheckedListBox^ AttackOpt;
	private: System::Windows::Forms::ComboBox^ targetPID;
	protected:


	protected:


	private:
		/// <summary>
		/// Erforderliche Designervariable.
		/// </summary>
		System::ComponentModel::Container^ components;

#pragma region Windows Form Designer generated code
		/// <summary>
		/// Erforderliche Methode f? die Designerunterst?zung.
		/// Der Inhalt der Methode darf nicht mit dem Code-Editor ge?dert werden.
		/// </summary>
		void InitializeComponent(void)
		{
			this->hookAndMonitoring = (gcnew System::Windows::Forms::Button());
			this->unhook = (gcnew System::Windows::Forms::Button());
			this->logBox = (gcnew System::Windows::Forms::TextBox());
			this->AttackOpt = (gcnew System::Windows::Forms::CheckedListBox());
			this->targetPID = (gcnew System::Windows::Forms::ComboBox());
			this->SuspendLayout();
			// 
			// hookAndMonitoring
			// 
			this->hookAndMonitoring->Location = System::Drawing::Point(12, 12);
			this->hookAndMonitoring->Name = L"hookAndMonitoring";
			this->hookAndMonitoring->Size = System::Drawing::Size(242, 82);
			this->hookAndMonitoring->TabIndex = 0;
			this->hookAndMonitoring->Text = L"Start";
			this->hookAndMonitoring->UseVisualStyleBackColor = true;
			this->hookAndMonitoring->Click += gcnew System::EventHandler(this, &Form1::hookAndMonitoring_Click);
			// 
			// unhook
			// 
			this->unhook->Location = System::Drawing::Point(274, 12);
			this->unhook->Name = L"unhook";
			this->unhook->Size = System::Drawing::Size(240, 82);
			this->unhook->TabIndex = 1;
			this->unhook->Text = L"Stop";
			this->unhook->UseVisualStyleBackColor = true;
			this->unhook->Click += gcnew System::EventHandler(this, &Form1::unhook_Click);
			// 
			// logBox
			// 
			this->logBox->Location = System::Drawing::Point(12, 351);
			this->logBox->Multiline = true;
			this->logBox->Name = L"logBox";
			this->logBox->ReadOnly = true;
			this->logBox->ScrollBars = System::Windows::Forms::ScrollBars::Both;
			this->logBox->Size = System::Drawing::Size(1044, 529);
			this->logBox->TabIndex = 2;
			// 
			// AttackOpt
			// 
			this->AttackOpt->Font = (gcnew System::Drawing::Font(L"±¼¸²", 10.875F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(129)));
			this->AttackOpt->FormattingEnabled = true;
			this->AttackOpt->Items->AddRange(gcnew cli::array< System::Object^  >(6) {
				L"#2 CodeViaCreateRemoteThread(LoadLibrayA)", L"#3 CodeViaCreateRemoteThread",
					L"#4 Suspendthread/Resumethread", L"#5 CodeViaQueueUserAPC(+AtomBombing)", L"#6 CtrlInject", L"#10 SetWindowLongPtrA"
			});
			this->AttackOpt->Location = System::Drawing::Point(12, 100);
			this->AttackOpt->Name = L"AttackOpt";
			this->AttackOpt->Size = System::Drawing::Size(751, 232);
			this->AttackOpt->TabIndex = 3;
			this->AttackOpt->SelectedIndexChanged += gcnew System::EventHandler(this, &Form1::AttackOpt_SelectedIndexChanged);
			// 
			// targetPID
			// 
			this->targetPID->Font = (gcnew System::Drawing::Font(L"±¼¸²", 12, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(129)));
			this->targetPID->FormattingEnabled = true;
			this->targetPID->Location = System::Drawing::Point(803, 292);
			this->targetPID->Name = L"targetPID";
			this->targetPID->Size = System::Drawing::Size(253, 40);
			this->targetPID->TabIndex = 4;
			this->targetPID->SelectedIndexChanged += gcnew System::EventHandler(this, &Form1::targetPID_SelectedIndexChanged);
			// 
			// Form1
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(13, 24);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->ClientSize = System::Drawing::Size(1085, 904);
			this->Controls->Add(this->targetPID);
			this->Controls->Add(this->AttackOpt);
			this->Controls->Add(this->logBox);
			this->Controls->Add(this->unhook);
			this->Controls->Add(this->hookAndMonitoring);
			this->Name = L"Form1";
			this->Text = L"FAST-Monitor";
			this->ResumeLayout(false);
			this->PerformLayout();

		}
#pragma endregion

	private: System::Void hookAndMonitoring_Click(System::Object^ sender, System::EventArgs^ e) {
		this->logBox->AppendText("Hook DLLs!\r\n\r\n");
		mon(0);

	}

	private: System::Void unhook_Click(System::Object^ sender, System::EventArgs^ e) {
		this->logBox->AppendText("Unhook DLLs!\r\n\r\n");
		mon(1);

	}

	public: Void logging(String^ text) {
		String^ pid = (String^)(text->Split(' '))[0];
		if(this->targetPID->Items->Contains(pid) != true)
			this->targetPID->Items->Add(pid);
		this->logBox->AppendText(text);
	}


	private: System::Void AttackOpt_SelectedIndexChanged(System::Object^ sender, System::EventArgs^ e) {
		
	}
	private: System::Void targetPID_SelectedIndexChanged(System::Object^ sender, System::EventArgs^ e) {

		if (this->targetPID->SelectedIndex > -1) {

		}

	}
	};

}


