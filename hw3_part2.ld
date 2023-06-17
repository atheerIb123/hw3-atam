ENTRY(_hw3_unicorn)

SECTIONS
{
 
  . = 0x60000;
  .data : 
  {
	*(.data)
	*(.bss)
  } :data = rw
  
  . = 0x400000;
  .text : 
  {
	*(.text)
  } :text = wx

  . = 0x80000000;
  .rodata : 
  {
	*(.rodata)
  } :rodata = rx
}

SYMBOLS
{
  purple = purple;
  white = white;	
}