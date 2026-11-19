" Vim syntax file
" Language:	klin

" For version 5.x: Clear all syntax items
" For version 6.x: Quit when a syntax file was already loaded
if version < 600
  syntax clear
elseif exists("b:current_syntax")
  finish
endif

if !exists("main_syntax")
  let main_syntax = 'klin'
endif

" Source HTML syntax
if version < 600
  source <sfile>:p:h/html.vim
else
  runtime! syntax/html.vim
endif
unlet b:current_syntax

" Next syntax items are case-sensitive
syn case match

" Include C syntax
syn include @cCode <sfile>:p:h/c.vim

syn region klinDecl matchgroup=klinTag start=/<%!/ keepend end=/%>/ contains=@cCode
syn region klinScript matchgroup=klinTag start=/<%/  keepend end=/%>/ contains=@cCode
syn region klinExpr matchgroup=klinTag start=/<%=/ keepend end=/%>/ contains=@cCode
syn region klinDirective start=/<%@/ end=/%>/ contains=htmlString,klinDirName,klinDirArg

syn keyword klinDirName contained include page taglib
syn keyword klinDirArg contained file uri prefix language extends import session buffer autoFlush
syn keyword klinDirArg contained isThreadSafe info errorPage contentType isErrorPage
syn keyword klinCommandName contained include 
syn keyword klinCommandArg contained name value 

" Define the default highlighting.
" For version 5.7 and earlier: only when not done already
" For version 5.8 and later: only when an item doesn't have highlighting yet
if version >= 508 || !exists("did_klin_syn_inits")
  if version < 508
    let did_klin_syn_inits = 1
    command -nargs=+ HiLink hi link <args>
  else
    command -nargs=+ HiLink hi def link <args>
  endif

  HiLink htmlComment     Comment
  HiLink htmlCommentPart Comment
  " Be consistent with html highlight settings
  HiLink klinTag          htmlTag
  HiLink klinDirective    klinTag
  HiLink klinDirName      htmlTagName
  HiLink klinDirArg       htmlArg
  HiLink klinCommand      klinTag
  HiLink klinCommandName  htmlTagName
  "HiLink klinCommandArg   htmlArg
  delcommand HiLink
endif

if main_syntax == 'klin'
  unlet main_syntax
endif

let b:current_syntax = "klin"

" vim: ts=8
