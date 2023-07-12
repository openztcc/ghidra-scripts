#include <idc.idc>

static FuncDump(f, start)
{
    auto ea, str, mangled_str, count, ref;
    auto end;
    auto teststr;

    ea = start;

    while( ea != BADADDR )
    {
        mangled_str = GetFunctionName(ea);
        if( mangled_str != 0 )
        {
            str = demangle_name(mangled_str, get_inf_attr(INF_LONG_DN));
            if(str == 0)
            {
                str = mangled_str;
            }
            end = FindFuncEnd(ea);

            count = 0;
            ref = RfirstB(ea);
            while(ref != BADADDR)
            {
                count = count + 1;
                ref = RnextB(ea, ref);
            }

            teststr = sprintf("sub_%X", ea);
            if( teststr != str )
            {
                fprintf(f, "%s, %s, 0x%X\n", mangled_str, str, ea);
            }
            //Message("%s, 0x%d, 0x%x, 0x%x, 0x%x, %d\n", str, count, ea, end, end-ea, end-ea   );
        }

        ea = NextFunction(ea);
    }
}

static main() 
{
    auto current = GetInputFile();
    current = AskFile(-1, current, "Where should I write the symbols to?");
    if(current == 0)
    {
        return -1;
    }
    auto f = fopen(current, "wb");
    Message("FuncDump: Start\n");

    FuncDump(f,0x00000);
    fclose(f);
    Message("FuncDump: Done\n");
}