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
<<<<<<< Updated upstream
=======
/// <summary>
/// flags
/// </summary>
#define FLAG_VirtualAllocEx 0b00000001
#define FLAG_NtMapViewOfSection 0b00000010
#define FLAG_VirtualProtectEx  0b00000100
#define FLAG_CreateRemoteThread 0b00001000
#define FLAG_SetWindowLongPtrA 0b00010000  
#define FLAG_SetPropA 0b00100000
#define FLAG_SetThreadContext 0b01000000
#define FLAG_NtQueueApcThread 0b10000000 
#define FLAG_WriteProcessMemory 0b10000000 

#define indexof( datum, data ) ( &datum - &*data.begin() )
>>>>>>> Stashed changes

void init();
void exiting();
<<<<<<< Updated upstream

static FILE* pFile = NULL;
static std::unordered_map<std::string, std::vector<std::pair<DWORD64, DWORD>>> rwxList;
=======
void vol(char* path, int op);

void imgui(std::vector<std::tuple<DWORD64, DWORD, std::string, UCHAR, std::string>> v);
static std::vector<std::vector<std::tuple<DWORD64, DWORD, std::string, UCHAR, std::string>>> detectionInfo;
static bool hooked = false;
extern std::string ghidraDirectory;
>>>>>>> Stashed changes

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
<<<<<<< Updated upstream
=======
	private: System::Windows::Forms::MenuStrip^ menuStrip1;
	private: System::Windows::Forms::ToolStripMenuItem^ monitoringToolStripMenuItem;
	private: System::Windows::Forms::ToolStripMenuItem^ startToolStripMenuItem;
	private: System::Windows::Forms::ToolStripMenuItem^ stopToolStripMenuItem;
	private: System::Windows::Forms::ToolStripMenuItem^ volatilityexeToolStripMenuItem;
	private: System::Windows::Forms::ToolStripMenuItem^ browserawToolStripMenuItem;
	private: System::Windows::Forms::OpenFileDialog^ openFileDialog1;

	private: System::Windows::Forms::ListView^ api_list;
	private: System::Windows::Forms::ColumnHeader^ api_name;
	private: System::Windows::Forms::ColumnHeader^ addr;
	private: System::Windows::Forms::ColumnHeader^ size;
	private: System::Windows::Forms::ColumnHeader^ caller_pid;
	private: System::Windows::Forms::ListView^ detected;

	private: System::Windows::Forms::ColumnHeader^ callee_pid;
	private: System::Windows::Forms::ColumnHeader^ attack_num;
	private: System::Windows::Forms::ColumnHeader^ timestamp;
	private: System::Windows::Forms::ToolStripMenuItem^ ghidraToolStripMenuItem;
	private: System::Windows::Forms::ToolStripMenuItem^ runGhidraToolStripMenuItem;
	private: System::Windows::Forms::ToolStripMenuItem^ setGhidraPathToolStripMenuItem;
	private: System::Windows::Forms::ToolStripMenuItem^ yarascanToolStripMenuItem;
	private: System::Windows::Forms::Button^ button1;

>>>>>>> Stashed changes
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
<<<<<<< Updated upstream
=======
			this->menuStrip1 = (gcnew System::Windows::Forms::MenuStrip());
			this->monitoringToolStripMenuItem = (gcnew System::Windows::Forms::ToolStripMenuItem());
			this->startToolStripMenuItem = (gcnew System::Windows::Forms::ToolStripMenuItem());
			this->stopToolStripMenuItem = (gcnew System::Windows::Forms::ToolStripMenuItem());
			this->volatilityexeToolStripMenuItem = (gcnew System::Windows::Forms::ToolStripMenuItem());
			this->browserawToolStripMenuItem = (gcnew System::Windows::Forms::ToolStripMenuItem());
			this->yarascanToolStripMenuItem = (gcnew System::Windows::Forms::ToolStripMenuItem());
			this->ghidraToolStripMenuItem = (gcnew System::Windows::Forms::ToolStripMenuItem());
			this->setGhidraPathToolStripMenuItem = (gcnew System::Windows::Forms::ToolStripMenuItem());
			this->runGhidraToolStripMenuItem = (gcnew System::Windows::Forms::ToolStripMenuItem());
			this->openFileDialog1 = (gcnew System::Windows::Forms::OpenFileDialog());
			this->api_list = (gcnew System::Windows::Forms::ListView());
			this->caller_pid = (gcnew System::Windows::Forms::ColumnHeader());
			this->addr = (gcnew System::Windows::Forms::ColumnHeader());
			this->size = (gcnew System::Windows::Forms::ColumnHeader());
			this->api_name = (gcnew System::Windows::Forms::ColumnHeader());
			this->detected = (gcnew System::Windows::Forms::ListView());
			this->callee_pid = (gcnew System::Windows::Forms::ColumnHeader());
			this->attack_num = (gcnew System::Windows::Forms::ColumnHeader());
			this->timestamp = (gcnew System::Windows::Forms::ColumnHeader());
			this->button1 = (gcnew System::Windows::Forms::Button());
			this->menuStrip1->SuspendLayout();
>>>>>>> Stashed changes
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
<<<<<<< Updated upstream
			this->targetPID->Size = System::Drawing::Size(253, 40);
			this->targetPID->TabIndex = 4;
			this->targetPID->SelectedIndexChanged += gcnew System::EventHandler(this, &Form1::targetPID_SelectedIndexChanged);
			// 
			// Form1
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(13, 24);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->ClientSize = System::Drawing::Size(1085, 904);
=======
			this->targetPID->Size = System::Drawing::Size(133, 24);
			this->targetPID->TabIndex = 4;
			this->targetPID->SelectedIndexChanged += gcnew System::EventHandler(this, &Form1::targetPID_SelectedIndexChanged);
			// 
			// menuStrip1
			// 
			this->menuStrip1->AutoSize = false;
			this->menuStrip1->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(235)), static_cast<System::Int32>(static_cast<System::Byte>(42)),
				static_cast<System::Int32>(static_cast<System::Byte>(83)));
			this->menuStrip1->Font = (gcnew System::Drawing::Font(L"µ¸¿ò", 9.75F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(129)));
			this->menuStrip1->ImageScalingSize = System::Drawing::Size(32, 32);
			this->menuStrip1->Items->AddRange(gcnew cli::array< System::Windows::Forms::ToolStripItem^  >(3) {
				this->monitoringToolStripMenuItem,
					this->volatilityexeToolStripMenuItem, this->ghidraToolStripMenuItem
			});
			this->menuStrip1->Location = System::Drawing::Point(0, 0);
			this->menuStrip1->Name = L"menuStrip1";
			this->menuStrip1->Padding = System::Windows::Forms::Padding(5, 1, 0, 1);
			this->menuStrip1->Size = System::Drawing::Size(782, 33);
			this->menuStrip1->TabIndex = 5;
			this->menuStrip1->Text = L"menuStrip1";
			// 
			// monitoringToolStripMenuItem
			// 
			this->monitoringToolStripMenuItem->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(235)),
				static_cast<System::Int32>(static_cast<System::Byte>(42)), static_cast<System::Int32>(static_cast<System::Byte>(83)));
			this->monitoringToolStripMenuItem->DropDownItems->AddRange(gcnew cli::array< System::Windows::Forms::ToolStripItem^  >(2) {
				this->startToolStripMenuItem,
					this->stopToolStripMenuItem
			});
			this->monitoringToolStripMenuItem->Font = (gcnew System::Drawing::Font(L"µ¸¿ò", 9.75F, System::Drawing::FontStyle::Bold));
			this->monitoringToolStripMenuItem->ForeColor = System::Drawing::Color::LightGray;
			this->monitoringToolStripMenuItem->Name = L"monitoringToolStripMenuItem";
			this->monitoringToolStripMenuItem->Size = System::Drawing::Size(88, 31);
			this->monitoringToolStripMenuItem->Text = L"Monitoring";
			// 
			// startToolStripMenuItem
			// 
			this->startToolStripMenuItem->Name = L"startToolStripMenuItem";
			this->startToolStripMenuItem->Size = System::Drawing::Size(112, 22);
			this->startToolStripMenuItem->Text = L"Start";
			this->startToolStripMenuItem->Click += gcnew System::EventHandler(this, &Form1::startToolStripMenuItem_Click);
			// 
			// stopToolStripMenuItem
			// 
			this->stopToolStripMenuItem->Name = L"stopToolStripMenuItem";
			this->stopToolStripMenuItem->Size = System::Drawing::Size(112, 22);
			this->stopToolStripMenuItem->Text = L"Stop";
			this->stopToolStripMenuItem->Click += gcnew System::EventHandler(this, &Form1::stopToolStripMenuItem_Click);
			// 
			// volatilityexeToolStripMenuItem
			// 
			this->volatilityexeToolStripMenuItem->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(235)),
				static_cast<System::Int32>(static_cast<System::Byte>(42)), static_cast<System::Int32>(static_cast<System::Byte>(83)));
			this->volatilityexeToolStripMenuItem->DropDownItems->AddRange(gcnew cli::array< System::Windows::Forms::ToolStripItem^  >(2) {
				this->browserawToolStripMenuItem,
					this->yarascanToolStripMenuItem
			});
			this->volatilityexeToolStripMenuItem->Font = (gcnew System::Drawing::Font(L"µ¸¿ò", 9.75F, System::Drawing::FontStyle::Bold));
			this->volatilityexeToolStripMenuItem->ForeColor = System::Drawing::Color::LightGray;
			this->volatilityexeToolStripMenuItem->Name = L"volatilityexeToolStripMenuItem";
			this->volatilityexeToolStripMenuItem->Size = System::Drawing::Size(75, 31);
			this->volatilityexeToolStripMenuItem->Text = L"Volatility";
			// 
			// browserawToolStripMenuItem
			// 
			this->browserawToolStripMenuItem->Name = L"browserawToolStripMenuItem";
			this->browserawToolStripMenuItem->Size = System::Drawing::Size(142, 22);
			this->browserawToolStripMenuItem->Text = L"malfind";
			this->browserawToolStripMenuItem->Click += gcnew System::EventHandler(this, &Form1::browserawToolStripMenuItem_Click);
			// 
			// yarascanToolStripMenuItem
			// 
			this->yarascanToolStripMenuItem->Name = L"yarascanToolStripMenuItem";
			this->yarascanToolStripMenuItem->Size = System::Drawing::Size(142, 22);
			this->yarascanToolStripMenuItem->Text = L"yarascan";
			this->yarascanToolStripMenuItem->Click += gcnew System::EventHandler(this, &Form1::yarascanToolStripMenuItem_Click);
			// 
			// ghidraToolStripMenuItem
			// 
			this->ghidraToolStripMenuItem->DropDownItems->AddRange(gcnew cli::array< System::Windows::Forms::ToolStripItem^  >(2) {
				this->setGhidraPathToolStripMenuItem,
					this->runGhidraToolStripMenuItem
			});
			this->ghidraToolStripMenuItem->Font = (gcnew System::Drawing::Font(L"µ¸¿ò", 9.75F, System::Drawing::FontStyle::Bold));
			this->ghidraToolStripMenuItem->ForeColor = System::Drawing::Color::LightGray;
			this->ghidraToolStripMenuItem->Name = L"ghidraToolStripMenuItem";
			this->ghidraToolStripMenuItem->Size = System::Drawing::Size(62, 31);
			this->ghidraToolStripMenuItem->Text = L"Ghidra";
			// 
			// setGhidraPathToolStripMenuItem
			// 
			this->setGhidraPathToolStripMenuItem->Name = L"setGhidraPathToolStripMenuItem";
			this->setGhidraPathToolStripMenuItem->Size = System::Drawing::Size(274, 22);
			this->setGhidraPathToolStripMenuItem->Text = L"Set Ghidra Directory Path";
			this->setGhidraPathToolStripMenuItem->Click += gcnew System::EventHandler(this, &Form1::setGhidraPathToolStripMenuItem_Click);
			// 
			// runGhidraToolStripMenuItem
			// 
			this->runGhidraToolStripMenuItem->Name = L"runGhidraToolStripMenuItem";
			this->runGhidraToolStripMenuItem->Size = System::Drawing::Size(274, 22);
			this->runGhidraToolStripMenuItem->Text = L"Run Ghidra and Open Project";
			this->runGhidraToolStripMenuItem->Click += gcnew System::EventHandler(this, &Form1::runGhidraToolStripMenuItem_Click);
			// 
			// openFileDialog1
			// 
			this->openFileDialog1->FileName = L"openFileDialog1";
			// 
			// api_list
			// 
			this->api_list->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((((System::Windows::Forms::AnchorStyles::Top | System::Windows::Forms::AnchorStyles::Bottom)
				| System::Windows::Forms::AnchorStyles::Left)
				| System::Windows::Forms::AnchorStyles::Right));
			this->api_list->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(35)), static_cast<System::Int32>(static_cast<System::Byte>(32)),
				static_cast<System::Int32>(static_cast<System::Byte>(39)));
			this->api_list->BorderStyle = System::Windows::Forms::BorderStyle::FixedSingle;
			this->api_list->Columns->AddRange(gcnew cli::array< System::Windows::Forms::ColumnHeader^  >(4) {
				this->caller_pid, this->addr,
					this->size, this->api_name
			});
			this->api_list->Font = (gcnew System::Drawing::Font(L"µ¸¿ò", 9.75F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(129)));
			this->api_list->ForeColor = System::Drawing::Color::White;
			this->api_list->HideSelection = false;
			this->api_list->Location = System::Drawing::Point(304, 35);
			this->api_list->Margin = System::Windows::Forms::Padding(2);
			this->api_list->Name = L"api_list";
			this->api_list->Size = System::Drawing::Size(472, 209);
			this->api_list->TabIndex = 7;
			this->api_list->UseCompatibleStateImageBehavior = false;
			this->api_list->View = System::Windows::Forms::View::Details;
			// 
			// caller_pid
			// 
			this->caller_pid->Text = L"Caller\'s PID";
			this->caller_pid->Width = 80;
			// 
			// addr
			// 
			this->addr->Text = L"address";
			this->addr->Width = 160;
			// 
			// size
			// 
			this->size->Text = L"size";
			this->size->Width = 58;
			// 
			// api_name
			// 
			this->api_name->Text = L"Windows API";
			this->api_name->Width = 174;
			// 
			// detected
			// 
			this->detected->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((((System::Windows::Forms::AnchorStyles::Top | System::Windows::Forms::AnchorStyles::Bottom)
				| System::Windows::Forms::AnchorStyles::Left)
				| System::Windows::Forms::AnchorStyles::Right));
			this->detected->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(35)), static_cast<System::Int32>(static_cast<System::Byte>(32)),
				static_cast<System::Int32>(static_cast<System::Byte>(39)));
			this->detected->BorderStyle = System::Windows::Forms::BorderStyle::FixedSingle;
			this->detected->Columns->AddRange(gcnew cli::array< System::Windows::Forms::ColumnHeader^  >(3) {
				this->callee_pid, this->attack_num,
					this->timestamp
			});
			this->detected->Font = (gcnew System::Drawing::Font(L"µ¸¿ò", 10.125F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(129)));
			this->detected->ForeColor = System::Drawing::Color::White;
			this->detected->HideSelection = false;
			this->detected->Location = System::Drawing::Point(5, 35);
			this->detected->Margin = System::Windows::Forms::Padding(2);
			this->detected->Name = L"detected";
			this->detected->Size = System::Drawing::Size(295, 209);
			this->detected->TabIndex = 8;
			this->detected->UseCompatibleStateImageBehavior = false;
			this->detected->View = System::Windows::Forms::View::Details;
			this->detected->SelectedIndexChanged += gcnew System::EventHandler(this, &Form1::detected_SelectedIndexChanged);
			this->detected->MouseDoubleClick += gcnew System::Windows::Forms::MouseEventHandler(this, &Form1::detected_MouseDoubleClick);
			// 
			// callee_pid
			// 
			this->callee_pid->Text = L"PID";
			// 
			// attack_num
			// 
			this->attack_num->Text = L"attack#";
			// 
			// timestamp
			// 
			this->timestamp->Text = L"timestamp";
			this->timestamp->Width = 175;
			// 
			// button1
			// 
			this->button1->Location = System::Drawing::Point(538, 5);
			this->button1->Name = L"button1";
			this->button1->Size = System::Drawing::Size(98, 21);
			this->button1->TabIndex = 9;
			this->button1->Text = L"WEB_LOG";
			this->button1->UseVisualStyleBackColor = true;
			this->button1->Click += gcnew System::EventHandler(this, &Form1::button1_Click);
			// 
			// Form1
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(8, 13);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(11)), static_cast<System::Int32>(static_cast<System::Byte>(7)),
				static_cast<System::Int32>(static_cast<System::Byte>(17)));
			this->ClientSize = System::Drawing::Size(782, 490);
			this->Controls->Add(this->button1);
			this->Controls->Add(this->detected);
			this->Controls->Add(this->api_list);
>>>>>>> Stashed changes
			this->Controls->Add(this->targetPID);
			this->Controls->Add(this->AttackOpt);
			this->Controls->Add(this->logBox);
			this->Controls->Add(this->unhook);
			this->Controls->Add(this->hookAndMonitoring);
			this->Name = L"Form1";
			this->Text = L"FAST-Monitor";
<<<<<<< Updated upstream
=======
			this->FormClosing += gcnew System::Windows::Forms::FormClosingEventHandler(this, &Form1::Form1_Closing);
			this->Load += gcnew System::EventHandler(this, &Form1::Form1_Load);
			this->menuStrip1->ResumeLayout(false);
			this->menuStrip1->PerformLayout();
>>>>>>> Stashed changes
			this->ResumeLayout(false);
			this->PerformLayout();

		}
#pragma endregion

<<<<<<< Updated upstream
	private: System::Void hookAndMonitoring_Click(System::Object^ sender, System::EventArgs^ e) {
		this->logBox->AppendText("Hook DLLs!\r\n\r\n");
		mon(0);

=======
	public: Void logging(std::string buf) {
		String^ text = gcnew String(buf.c_str());
		String^ pid = (String^)(text->Split(' '))[0];
		if (this->targetPID->Items->Contains(pid) != true)
			this->targetPID->Items->Add(pid);
		this->logBox->AppendText(text);

	}


	public: Void show_detection(std::string callee_pid, std::vector< std::tuple<DWORD64, DWORD, std::string, UCHAR, std::string>> v) {

		System::Windows::Forms::ListViewItem^ item = gcnew System::Windows::Forms::ListViewItem(gcnew String(callee_pid.c_str()));
		item->SubItems->Add(gcnew String(std::get<3>(v[0]).ToString()));
		System::DateTime^ dt = gcnew System::DateTime();
		item->SubItems->Add(dt->Now.ToString("yyyy-MM-dd-HH-mm-ss"));

		this->detected->Items->Add(item);

		//###################
		detectionInfo.push_back(v);


	}


	private: System::Void targetPID_SelectedIndexChanged(System::Object^ sender, System::EventArgs^ e) {

		if (this->targetPID->SelectedIndex > -1) {

		}

	}
	private: System::Void Form1_Load(System::Object^ sender, System::EventArgs^ e) {
	}
	private: System::Void Form1_Closing(System::Object^ sender, System::Windows::Forms::FormClosingEventArgs^ e) {
		if (hooked) {
			Diagnostics::Process^ proc = Diagnostics::Process::Start("hook-dll.exe", "off");
			proc->WaitForExit();
		}
	}
	private: System::Void startToolStripMenuItem_Click(System::Object^ sender, System::EventArgs^ e) {
		this->logBox->AppendText("Hook DLLs!\r\n\r\n");
		Diagnostics::Process^ proc = Diagnostics::Process::Start("hook-dll.exe", "on");
		proc->WaitForExit();
		hooked = true;
>>>>>>> Stashed changes
	}

	private: System::Void unhook_Click(System::Object^ sender, System::EventArgs^ e) {
		this->logBox->AppendText("Unhook DLLs!\r\n\r\n");
<<<<<<< Updated upstream
		mon(1);
=======
		Diagnostics::Process^ proc = Diagnostics::Process::Start("hook-dll.exe", "off");
		proc->WaitForExit();
		hooked = false;
	}
	private: System::Void browserawToolStripMenuItem_Click(System::Object^ sender, System::EventArgs^ e) {

		System::Windows::Forms::DialogResult dr = this->openFileDialog1->ShowDialog();

		if (System::Windows::Forms::DialogResult::OK == dr) {
			char* path = (char*)(void*)Marshal::StringToHGlobalAnsi(this->openFileDialog1->FileName);
			vol(path, 0);
			Marshal::FreeHGlobal((System::IntPtr)path);
		}
	}
	private: System::Void yarascanToolStripMenuItem_Click(System::Object^ sender, System::EventArgs^ e) {
		System::Windows::Forms::DialogResult dr = this->openFileDialog1->ShowDialog();
>>>>>>> Stashed changes

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
<<<<<<< Updated upstream
	};

=======

	private: std::string getAPI(UCHAR flags) {

		if (flags & FLAG_VirtualAllocEx)
			return std::string("VirtualAllocEx");
		if (flags & FLAG_NtMapViewOfSection)
			return std::string("NtMapViewOfSection");
		if (flags & FLAG_VirtualProtectEx)
			return std::string("VirtualProtectEx");

		if (flags == FLAG_WriteProcessMemory)
			return std::string("WriteProcessMemory");


		if (flags == FLAG_CreateRemoteThread)
			return std::string("CreateRemoteThread");
		if (flags == FLAG_SetWindowLongPtrA)
			return std::string("SetWindowLongPtrA");
		if (flags == FLAG_SetPropA)
			return std::string("SetPropA");
		if (flags == FLAG_SetThreadContext)
			return std::string("SetThreadContext");

		return std::string("");
	}

	private: System::Void button1_Click(System::Object^ sender, System::EventArgs^ e) {
		System::Diagnostics::Process::Start("http://localhost/index.php");
	}
};
>>>>>>> Stashed changes
}


