#pragma once



void attack(unsigned int pid, unsigned int tid, int method, int payload_type);
void init();
void exiting();

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
			if (components)
			{
				delete components;
			}
			exiting();
		}
	private: System::Windows::Forms::Button^ attack_button;
	private: System::Windows::Forms::TextBox^ pid_input;
	private: System::Windows::Forms::TextBox^ tid_input;
	private: System::Windows::Forms::Label^ pid_label;
	private: System::Windows::Forms::Label^ tid_label;
	private: System::Windows::Forms::ComboBox^ options;
	private: System::Windows::Forms::Label^ option_label;
	private: System::Windows::Forms::Label^ status;
	private: System::Windows::Forms::RadioButton^ dll_opt;
	private: System::Windows::Forms::RadioButton^ shellcode_opt;

	private: int payload_type = 0;

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
			this->attack_button = (gcnew System::Windows::Forms::Button());
			this->pid_input = (gcnew System::Windows::Forms::TextBox());
			this->tid_input = (gcnew System::Windows::Forms::TextBox());
			this->pid_label = (gcnew System::Windows::Forms::Label());
			this->tid_label = (gcnew System::Windows::Forms::Label());
			this->options = (gcnew System::Windows::Forms::ComboBox());
			this->option_label = (gcnew System::Windows::Forms::Label());
			this->status = (gcnew System::Windows::Forms::Label());
			this->dll_opt = (gcnew System::Windows::Forms::RadioButton());
			this->shellcode_opt = (gcnew System::Windows::Forms::RadioButton());
			this->SuspendLayout();
			// 
			// attack_button
			// 
			this->attack_button->Location = System::Drawing::Point(918, 39);
			this->attack_button->Name = L"attack_button";
			this->attack_button->Size = System::Drawing::Size(194, 102);
			this->attack_button->TabIndex = 0;
			this->attack_button->Text = L"Attack";
			this->attack_button->UseVisualStyleBackColor = true;
			this->attack_button->Click += gcnew System::EventHandler(this, &Form1::attack_button_Click);
			// 
			// pid_input
			// 
			this->pid_input->Location = System::Drawing::Point(32, 89);
			this->pid_input->Name = L"pid_input";
			this->pid_input->Size = System::Drawing::Size(153, 35);
			this->pid_input->TabIndex = 1;
			// 
			// tid_input
			// 
			this->tid_input->Location = System::Drawing::Point(256, 89);
			this->tid_input->Name = L"tid_input";
			this->tid_input->Size = System::Drawing::Size(157, 35);
			this->tid_input->TabIndex = 2;
			// 
			// pid_label
			// 
			this->pid_label->AutoSize = true;
			this->pid_label->Location = System::Drawing::Point(28, 39);
			this->pid_label->Name = L"pid_label";
			this->pid_label->Size = System::Drawing::Size(118, 24);
			this->pid_label->TabIndex = 3;
			this->pid_label->Text = L"Target PID";
			// 
			// tid_label
			// 
			this->tid_label->AutoSize = true;
			this->tid_label->Location = System::Drawing::Point(252, 39);
			this->tid_label->Name = L"tid_label";
			this->tid_label->Size = System::Drawing::Size(117, 24);
			this->tid_label->TabIndex = 4;
			this->tid_label->Text = L"Target TID";
			// 
			// options
			// 
			this->options->FormattingEnabled = true;
			this->options->Items->AddRange(gcnew cli::array< System::Object^  >(6) {
				L"#1 : CreateRemoteThread(VirtualAllocEx, WriteProcessMemory)",
					L"#2 : CreateRemoteThread(CreateFileMappingA, MapViewOfFile, NtMapViewOfSection)", L"#3 : AtomBombing(QueueUserAPC, GlobalAddAtomA, GlobalGetAtomNameA, NtQueueApcThre"
					L"ad)",
					L"#4 : ThreadHijacking(SuspendThread, SetThreadContext, ResumeThread, VirtualAllocE"
					L"x)", L"#5 : SetWindowLongPtrA(SetWindowLongPtrA, VirtualAllocEx, WriteProcessMemory)",
					L"#6 : CtrlInject(SendInput, PostMessageA, VirtualAllocEx, WriteProcessMemory)"
			});
			this->options->Location = System::Drawing::Point(32, 234);
			this->options->Name = L"options";
			this->options->Size = System::Drawing::Size(1080, 32);
			this->options->TabIndex = 5;
			// 
			// option_label
			// 
			this->option_label->AutoSize = true;
			this->option_label->Location = System::Drawing::Point(28, 170);
			this->option_label->Name = L"option_label";
			this->option_label->Size = System::Drawing::Size(290, 24);
			this->option_label->TabIndex = 6;
			this->option_label->Text = L"Option : #3 is not Working.";
			// 
			// status
			// 
			this->status->AutoSize = true;
			this->status->ForeColor = System::Drawing::Color::Red;
			this->status->Location = System::Drawing::Point(529, 39);
			this->status->Name = L"status";
			this->status->Size = System::Drawing::Size(0, 24);
			this->status->TabIndex = 7;
			// 
			// dll_opt
			// 
			this->dll_opt->AutoSize = true;
			this->dll_opt->Checked = true;
			this->dll_opt->Location = System::Drawing::Point(533, 113);
			this->dll_opt->Name = L"dll_opt";
			this->dll_opt->Size = System::Drawing::Size(286, 28);
			this->dll_opt->TabIndex = 8;
			this->dll_opt->TabStop = true;
			this->dll_opt->Text = L"Reflective DLL Injection";
			this->dll_opt->UseVisualStyleBackColor = true;
			this->dll_opt->CheckedChanged += gcnew System::EventHandler(this, &Form1::dll_opt_CheckedChanged);
			// 
			// shellcode_opt
			// 
			this->shellcode_opt->AutoSize = true;
			this->shellcode_opt->Location = System::Drawing::Point(535, 168);
			this->shellcode_opt->Name = L"shellcode_opt";
			this->shellcode_opt->Size = System::Drawing::Size(235, 28);
			this->shellcode_opt->TabIndex = 9;
			this->shellcode_opt->Text = L"Shellcode Injection";
			this->shellcode_opt->UseVisualStyleBackColor = true;
			this->shellcode_opt->CheckedChanged += gcnew System::EventHandler(this, &Form1::shellcode_opt_CheckedChanged);
			// 
			// Form1
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(13, 24);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->ClientSize = System::Drawing::Size(1137, 315);
			this->Controls->Add(this->shellcode_opt);
			this->Controls->Add(this->dll_opt);
			this->Controls->Add(this->status);
			this->Controls->Add(this->option_label);
			this->Controls->Add(this->options);
			this->Controls->Add(this->tid_label);
			this->Controls->Add(this->pid_label);
			this->Controls->Add(this->tid_input);
			this->Controls->Add(this->pid_input);
			this->Controls->Add(this->attack_button);
			this->Name = L"Form1";
			this->Text = L"fast-attack_tool";
			this->ResumeLayout(false);
			this->PerformLayout();

		}
#pragma endregion
	private: System::Void attack_button_Click(System::Object^ sender, System::EventArgs^ e) {
		attack(this->pid_input->Text->Length ? UInt32::Parse(this->pid_input->Text) : 0,
			this->tid_input->Text->Length ? UInt32::Parse(this->tid_input->Text) : 0,
			this->options->SelectedIndex + 1, this->payload_type);
	}

	public: System::Void set_status(System::String^ str) {
		this->status->Text = str;
	}

	private: System::Void dll_opt_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {
		this->payload_type = 0;
	}
	private: System::Void shellcode_opt_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {
		this->payload_type = 1;
	}
	};
}
