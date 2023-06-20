ENTRY(_hw3_unicorn)

PHDRS
{
data PT_LOAD FLAGS(0x6) ;
text PT_LOAD FLAGS(0x3) ;
rodata PT_LOAD FLAGS(0x5) ;
}

EXTERN(purple)
EXTERN(white)

SECTIONS
{
  . = 0x60000;
  .data : 
  {
	*(.data)
	*(.bss)
  } :data
  
  . = 0x400000;
  .text : 
  {
	*(.text)
  } :text

  . = 0x80000000;
  .rodata : 
  {
	*(.rodata)
  } :rodata 

}