__int64 __fastcall transform_input(__int64 a1)
{
  unsigned __int64 v1; // rax@7
  __int64 v2; // rax@12
  __int64 v4; // rax@24
  __int64 v5; // rax@25
  __int64 v6; // rax@31
  __int64 v7; // rax@32
  __int64 v8; // [sp+0h] [bp-50h]@4
  __int64 v9; // [sp+8h] [bp-48h]@24
  unsigned int v10; // [sp+14h] [bp-3Ch]@20
  bool v11; // [sp+1Bh] [bp-35h]@19
  bool v12; // [sp+1Ch] [bp-34h]@16
  bool v13; // [sp+1Dh] [bp-33h]@12
  bool v14; // [sp+1Eh] [bp-32h]@7
  bool v15; // [sp+1Fh] [bp-31h]@7
  unsigned __int64 v16; // [sp+20h] [bp-30h]@7
  __int64 *v17; // [sp+28h] [bp-28h]@4
  __int64 *v18; // [sp+30h] [bp-20h]@4
  bool v19; // [sp+3Fh] [bp-11h]@2
  __int64 v20; // [sp+40h] [bp-10h]@1

  v20 = a1;
  do
    v19 = y12 < 10 || (((_BYTE)x11 - 1) * (_BYTE)x11 & 1) == 0;
  while ( y2 >= 10 && (((_BYTE)x1 - 1) * (_BYTE)x1 & 1) != 0 );
  if ( !v19 )
    goto LABEL_23;
  while ( 1 )
  {
    *((_DWORD *)&v8 - 4) = 0;
    *((_DWORD *)&v8 - 4) = 0;
    v18 = &v8 - 2;
    v17 = &v8 - 2;
    if ( y12 < 10 || (((_BYTE)x11 - 1) * (_BYTE)x11 & 1) == 0 )
      break;
LABEL_23:
    *((_DWORD *)&v8 - 4) = 0;
    *((_DWORD *)&v8 - 4) = 0;
  }
LABEL_5:
  if ( y12 >= 10 && (((_BYTE)x11 - 1) * (_BYTE)x11 & 1) != 0 )
    goto LABEL_24;
  while ( 1 )
  {
    if ( y2 >= 10 && (((_BYTE)x1 - 1) * (_BYTE)x1 & 1) != 0 )
      goto LABEL_31;
    while ( 1 )
    {
      v16 = *(_DWORD *)v17;
      LODWORD(v1) = std::vector<int,std::allocator<int>>::size(v20);
      v15 = v16 < v1;
      v14 = y12 < 10 || (((_BYTE)x11 - 1) * (_BYTE)x11 & 1) == 0;
      if ( y2 < 10 || (((_BYTE)x1 - 1) * (_BYTE)x1 & 1) == 0 )
        break;
LABEL_31:
      LODWORD(v6) = std::vector<int,std::allocator<int>>::size(v20);
      v8 = v6;
    }
    if ( v14 )
      break;
LABEL_24:
    LODWORD(v4) = std::vector<int,std::allocator<int>>::size(v20);
    v9 = v4;
  }
  if ( v15 )
  {
    if ( y12 >= 10 && (((_BYTE)x11 - 1) * (_BYTE)x11 & 1) != 0 )
      goto LABEL_25;
    while ( 2 )
    {
      if ( y2 >= 10 && (((_BYTE)x1 - 1) * (_BYTE)x1 & 1) != 0 )
        goto LABEL_32;
      while ( 1 )
      {
        LODWORD(v2) = std::vector<int,std::allocator<int>>::operator[](v20, *(_DWORD *)v17);
        *(_DWORD *)v18 += *(_DWORD *)v2;
        v13 = y12 < 10 || (((_BYTE)x11 - 1) * (_BYTE)x11 & 1) == 0;
        if ( y2 < 10 || (((_BYTE)x1 - 1) * (_BYTE)x1 & 1) == 0 )
          break;
LABEL_32:
        LODWORD(v7) = std::vector<int,std::allocator<int>>::operator[](v20, *(_DWORD *)v17);
        *(_DWORD *)v18 += *(_DWORD *)v7;
      }
      if ( !v13 )
      {
LABEL_25:
        LODWORD(v5) = std::vector<int,std::allocator<int>>::operator[](v20, *(_DWORD *)v17);
        *(_DWORD *)v18 += *(_DWORD *)v5;
        continue;
      }
      break;
    }
    if ( y12 >= 10 && (((_BYTE)x11 - 1) * (_BYTE)x11 & 1) != 0 )
      goto LABEL_26;
LABEL_15:
    if ( y2 >= 10 && (((_BYTE)x1 - 1) * (_BYTE)x1 & 1) != 0 )
      goto LABEL_33;
    while ( 1 )
    {
      ++*(_DWORD *)v17;
      v12 = y12 < 10 || (((_BYTE)x11 - 1) * (_BYTE)x11 & 1) == 0;
      if ( y2 < 10 || (((_BYTE)x1 - 1) * (_BYTE)x1 & 1) == 0 )
      {
        if ( v12 )
          goto LABEL_5;
LABEL_26:
        if ( y2 >= 10 && (((_BYTE)x1 - 1) * (_BYTE)x1 & 1) != 0 )
          goto LABEL_36;
        while ( 1 )
        {
          ++*(_DWORD *)v17;
          if ( y2 < 10 || (((_BYTE)x1 - 1) * (_BYTE)x1 & 1) == 0 )
            break;
LABEL_36:
          ++*(_DWORD *)v17;
        }
        goto LABEL_15;
      }
LABEL_33:
      ++*(_DWORD *)v17;
    }
  }
  do
    v11 = y12 < 10 || (((_BYTE)x11 - 1) * (_BYTE)x11 & 1) == 0;
  while ( y2 >= 10 && (((_BYTE)x1 - 1) * (_BYTE)x1 & 1) != 0 );
  do
    v10 = *(_DWORD *)v18;
  while ( y12 >= 10 && (((_BYTE)x11 - 1) * (_BYTE)x11 & 1) != 0 );
  while ( y2 >= 10 && (((_BYTE)x1 - 1) * (_BYTE)x1 & 1) != 0 )
    ;
  return v10;
}

__int64 __fastcall sanitize_input(std::string *a1)
{
  __int64 v1; // rax@11
  __int64 v2; // rdx@18
  __int64 v3; // rax@23
  __int64 v4; // rax@27
  __int64 v5; // rsi@41
  __int64 v6; // rax@42
  __int64 v7; // rax@62
  __int64 v9; // [sp+0h] [bp-180h]@4
  __int64 *v10; // [sp+18h] [bp-168h]@68
  unsigned int v11; // [sp+44h] [bp-13Ch]@65
  __int64 v12; // [sp+48h] [bp-138h]@62
  bool v13; // [sp+52h] [bp-12Eh]@60
  bool v14; // [sp+53h] [bp-12Dh]@54
  bool v15; // [sp+54h] [bp-12Ch]@50
  bool v16; // [sp+55h] [bp-12Bh]@46
  bool v17; // [sp+56h] [bp-12Ah]@46
  __int64 v18; // [sp+80h] [bp-100h]@42
  __int64 v19; // [sp+88h] [bp-F8h]@41
  int v20; // [sp+90h] [bp-F0h]@41
  bool v21; // [sp+96h] [bp-EAh]@38
  bool v22; // [sp+97h] [bp-E9h]@35
  int v23; // [sp+98h] [bp-E8h]@34
  bool v24; // [sp+9Fh] [bp-E1h]@31
  int v25; // [sp+A0h] [bp-E0h]@29
  bool v26; // [sp+A7h] [bp-D9h]@28
  __int64 v27; // [sp+A8h] [bp-D8h]@27
  __int64 v28; // [sp+B0h] [bp-D0h]@26
  bool v29; // [sp+BEh] [bp-C2h]@23
  bool v30; // [sp+BFh] [bp-C1h]@21
  unsigned __int64 v31; // [sp+C0h] [bp-C0h]@20
  bool v32; // [sp+CFh] [bp-B1h]@18
  __int64 v33; // [sp+D0h] [bp-B0h]@18
  bool v34; // [sp+DFh] [bp-A1h]@15
  __int64 v35; // [sp+E0h] [bp-A0h]@11
  bool v36; // [sp+EFh] [bp-91h]@8
  __int64 v37; // [sp+F0h] [bp-90h]@8
  bool v38; // [sp+FEh] [bp-82h]@7
  bool v39; // [sp+FFh] [bp-81h]@5
  __int64 v40; // [sp+100h] [bp-80h]@4
  __int64 v41; // [sp+108h] [bp-78h]@4
  __int64 *v42; // [sp+110h] [bp-70h]@4
  __int64 *v43; // [sp+118h] [bp-68h]@4
  __int64 *v44; // [sp+120h] [bp-60h]@4
  __int64 *v45; // [sp+128h] [bp-58h]@4
  __int64 *v46; // [sp+130h] [bp-50h]@4
  unsigned int *v47; // [sp+138h] [bp-48h]@4
  __int64 *v48; // [sp+140h] [bp-40h]@4
  bool v49; // [sp+14Fh] [bp-31h]@2
  std::string *v50; // [sp+150h] [bp-30h]@1

  v50 = a1;
  do
    v49 = y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0;
  while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 );
  if ( !v49 )
    goto LABEL_68;
  while ( 1 )
  {
    v48 = &v9 - 2;
    v47 = (unsigned int *)(&v9 - 2);
    v46 = &v9 - 4;
    v45 = &v9 - 2;
    v44 = &v9 - 2;
    v43 = &v9 - 2;
    v42 = &v9 - 2;
    v41 = (__int64)(&v9 - 2);
    v40 = (__int64)(&v9 - 4);
    std::vector<int,std::allocator<int>>::vector(&v9 - 4);
    *(_DWORD *)v45 = 0;
    if ( y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0 )
      break;
LABEL_68:
    v10 = &v9 - 2;
    std::vector<int,std::allocator<int>>::vector(&v9 - 4);
    *(_DWORD *)v10 = 0;
  }
  while ( 1 )
  {
    do
      v39 = *(_DWORD *)v45 < legend >> 2;
    while ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 );
    if ( !v39 )
    {
      do
        v13 = y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0;
      while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 );
      while ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 )
        ;
      LODWORD(v7) = std::operator<<<std::char_traits<char>>(6357472LL, 4253236LL);
      v12 = v7;
      if ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 )
        goto LABEL_91;
      while ( 1 )
      {
        *v47 = 4919;
        *(_DWORD *)v43 = 1;
        if ( y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0 )
          goto LABEL_64;
LABEL_91:
        *v47 = 4919;
        *(_DWORD *)v43 = 1;
      }
    }
    do
      v38 = y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0;
    while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 );
    do
    {
      do
      {
        v37 = *(_DWORD *)v45;
        v36 = y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0;
      }
      while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 );
    }
    while ( !v36 );
    while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 )
      ;
    LODWORD(v1) = std::string::operator[](v50, v37);
    v35 = v1;
    if ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 )
    {
LABEL_71:
      if ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 )
        goto LABEL_114;
      while ( 1 )
      {
        *(_DWORD *)v44 = *(_BYTE *)v35;
        if ( y4 < 10 || (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) == 0 )
          break;
LABEL_114:
        *(_DWORD *)v44 = *(_BYTE *)v35;
      }
    }
    *(_DWORD *)v44 = *(_BYTE *)v35;
    if ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 )
      goto LABEL_71;
    while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 )
      ;
    std::vector<int,std::allocator<int>>::push_back(v46, v44);
    do
      v34 = y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0;
    while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 );
    if ( !v34 )
LABEL_74:
      *(_DWORD *)v41 = *(_DWORD *)v45;
    if ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 )
LABEL_99:
      *(_DWORD *)v41 = *(_DWORD *)v45;
    v2 = v41;
    *(_DWORD *)v41 = *(_DWORD *)v45;
    v33 = *(_DWORD *)v2;
    v32 = y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0;
    if ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 )
      goto LABEL_99;
    if ( !v32 )
      goto LABEL_74;
    v31 = std::string::length(v50);
    do
      v30 = y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0;
    while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 );
    if ( !v30 )
LABEL_75:
      *(_DWORD *)v41 = (v31 >> 40) & v33 | 0x1C;
    v3 = v41;
    *(_DWORD *)v41 = (v31 >> 40) & v33 | 0x1C;
    v29 = *(_DWORD *)v3 != 0;
    if ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 )
      goto LABEL_75;
    while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 )
      ;
    if ( v29 )
    {
      do
        v28 = *(_DWORD *)v45;
      while ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 );
      LODWORD(v4) = std::vector<int,std::allocator<int>>::operator[](6357752LL, v28);
      v27 = v4;
      do
        v26 = y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0;
      while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 );
      do
        v25 = *(_DWORD *)v27;
      while ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 );
      std::vector<int,std::allocator<int>>::vector(v40, v46);
      do
        v24 = y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0;
      while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 );
      while ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 )
        ;
      while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 )
        ;
      v23 = transform_input(v40);
      if ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 )
        goto LABEL_79;
      while ( 1 )
      {
        v22 = v25 == v23;
        if ( y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0 )
        {
          while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 )
            ;
          std::vector<int,std::allocator<int>>::~vector(v40);
          do
            v21 = y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0;
          while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 );
          while ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 )
            ;
          if ( v22 )
          {
            do
            {
              v5 = *(_DWORD *)v45;
              v20 = *(_DWORD *)v41;
              v19 = v5;
            }
            while ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 );
            LODWORD(v6) = std::vector<int,std::allocator<int>>::operator[](6357752LL, v19);
            v18 = v6;
            if ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 )
              goto LABEL_83;
            while ( 1 )
            {
              *(_DWORD *)v41 = (*(_DWORD *)v18 & v20) < 0;
              if ( y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0 )
                break;
LABEL_83:
              *(_DWORD *)v41 = (*(_DWORD *)v18 & v20) < 0;
            }
          }
          if ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 )
            goto LABEL_84;
          while ( 1 )
          {
            if ( y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0 )
              goto LABEL_46;
LABEL_84:
            while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 )
              ;
          }
        }
LABEL_79:
        while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 )
          ;
      }
    }
    do
    {
      do
      {
LABEL_46:
        v17 = *(_DWORD *)v41 != 0;
        v16 = y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0;
      }
      while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 );
    }
    while ( !v16 );
    while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 )
      ;
    if ( v17 )
      break;
    do
      v14 = y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0;
    while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 );
    while ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 )
      ;
    while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 )
      ;
    if ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 )
LABEL_89:
      ++*(_DWORD *)v45;
    ++*(_DWORD *)v45;
    if ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 )
      goto LABEL_89;
  }
  do
    v15 = y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0;
  while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 );
  if ( !v15 )
    goto LABEL_87;
  while ( 1 )
  {
    *v47 = ((unsigned __int16)*(_DWORD *)v45 << 8) & 0x147;
    *(_DWORD *)v43 = 1;
    if ( y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0 )
      break;
LABEL_87:
    *v47 = ((unsigned __int16)*(_DWORD *)v45 << 8) & 0x147;
    *(_DWORD *)v43 = 1;
  }
LABEL_64:
  if ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 )
    goto LABEL_92;
  while ( 1 )
  {
    std::vector<int,std::allocator<int>>::~vector(v46);
    v11 = *v47;
    if ( y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0 )
      break;
LABEL_92:
    std::vector<int,std::allocator<int>>::~vector(v46);
  }
  while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 )
    ;
  return v11;
}