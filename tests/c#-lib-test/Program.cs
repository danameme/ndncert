using System;

using System.Runtime.InteropServices;

namespace myApp
{
    class Program
    {

	[DllImport("libclientcwrapper.so", EntryPoint="InvokeClient_Call_Main")]
        static extern int InvokeClient_Call_Main(string classname, string p_index, string p_namespace, string p_challenge);

        static void Main(string[] args)
        {
	    Program p = new Program();
            Console.WriteLine("Hello World! " + p.PrintName("Bob"));

	    Console.WriteLine("Begin calling C wrapper function...");
	    int ret = InvokeClient_Call_Main("InvokeClient", "0", "nmsu4", "NOCHALL");

	    Console.WriteLine("End of C# program");
        }

	string PrintName(string yourname)
	{
		return "Welcome " + yourname;
	}
    }
}
