//===- ML.h - Sema ML extensions ---------------------------------*- C++-*-===//
//
// See ML_LICENSE.txt for license information.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_SEMA_ML_H
#define LLVM_CLANG_SEMA_ML_H

#include "clang/AST/AST.h"
#include "llvm/ADT/SetVector.h"

namespace clang {
class LookupResult;
class ParsedAttr;

class SemaML {
  friend class Parser;
  friend class Sema;

public:
  enum HookBaseKind {
    Unknown,
    Simple, // we have one well defined candidate
    Lookup, // we have multiple candidates
  };

  Sema &S;

protected:
  bool ParsingExtendsKW = false;
  bool HandlingHookArgs = false;
  bool HandlingTilde = false;

  SemaML(Sema &SemaRef) : S(SemaRef) {}

  ASTContext &GetContext();
  IdentifierInfo *GetIdentifier(StringRef Name);

  ExprResult LookupHookBaseImpl(CXXRecordDecl *Base, LookupResult &R);
  CXXMethodDecl *LookupBuiltinImpl(CXXRecordDecl *E, const IdentifierInfo *II,
                                   SourceLocation Loc);

public:
  template <typename Attr, typename... Args>
  void AddSillyAttr(Decl *D, Args... args) {
    AttributeFactory AF;
    ParsedAttributes PA(AF);
    auto &Context = GetContext();
    PA.addNew(GetIdentifier("silly"), SourceRange(), nullptr, SourceLocation(),
              nullptr, 0u, AttributeCommonInfo::AS_Keyword, SourceLocation());
    D->addAttr(::new (Context) Attr(Context, PA.back(), args...));
  }

  bool IsMLNamespace(const DeclContext *DC);
  bool IsInMLNamespace(const Decl *D);

  DeclarationNameInfo BuildDNI(const IdentifierInfo *II, SourceLocation Loc);

  bool InjectSuperKW(CXXRecordDecl *E, TypeSourceInfo *B);
  bool IsInHookScope();

  ExprResult LookupHookMemberBase(CXXRecordDecl *Base,
                                  const DeclarationNameInfo &DNI);
  ExprResult LookupHookDtorBase(CXXRecordDecl *Base);

  CXXMethodDecl *LookupBuiltinSelf(CXXRecordDecl *E, SourceLocation Loc,
                                   bool Mutable);
  CXXMethodDecl *LookupBuiltinDtorHook(CXXRecordDecl *MD);

  HookBaseKind GetHookBaseKind(Expr *BaseExpr);
  FunctionDecl *HandleSimpleBase(FunctionDecl *H, Expr *BaseExpr);
  FunctionDecl *HandleLookupBase(FunctionDecl *H, Expr *BaseExpr,
                                 CXXRecordDecl *ClassBase);
  FunctionDecl *ValidateHookBase(FunctionDecl *H, FunctionDecl *B);

  FunctionDecl *FetchBaseOfHook(FunctionDecl *H, Expr *BaseExpr);
  FunctionDecl *LookupBaseOfHook(FunctionDecl *H);
  TypeSourceInfo *AttachBaseToExtension(CXXRecordDecl *E, TypeSourceInfo *B);
};

/// Attribute handlers.

void handleDynamicLinkageAttr(Sema &S, Decl *D, const ParsedAttr &AL);
void handleHookAttr(Sema &S, Decl *D, const ParsedAttr &AL);
void handleRecordExtensionAttr(Sema &S, Decl *D, const ParsedAttr &AL);
void handleNoDeallocatorAttr(Sema &S, Decl *D, const ParsedAttr &AL);
} // namespace clang

#endif // LLVM_CLANG_SEMA_ML_H