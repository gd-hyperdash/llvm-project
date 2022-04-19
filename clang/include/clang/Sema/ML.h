//===- ML.h - Sema ML extensions ---------------------------------*- C++ -*-===//
//
// See ML_LICENSE.txt for license information.
//
//===-----------------------------------------------------------------------===//

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
  bool HandlingHookArgs = false;
  bool HandlingTilde = false;

  /// Cache for "link_name", used to prevent defining the
  /// same symbol more than once.
  llvm::SetVector<StringRef> LinkNameCache;

  SemaML(Sema &SemaRef) : S(SemaRef) {}

  ExprResult LookupHookBaseImpl(CXXRecordDecl *Base, LookupResult &R);

public:
  void cacheLinkName(StringRef S) { LinkNameCache.insert(S); }
  bool hasLinkNameCached(StringRef S) { return LinkNameCache.contains(S); }

  ExprResult LookupHookMemberBase(CXXRecordDecl *Base,
                                  const DeclarationNameInfo &DNI);
  ExprResult LookupHookDtorBase(CXXRecordDecl *Base);

  HookBaseKind GetHookBaseKind(Expr *BaseExpr);
  FunctionDecl *HandleSimpleBase(FunctionDecl *H, Expr *BaseExpr);
  FunctionDecl *HandleLookupBase(FunctionDecl *H, Expr *BaseExpr,
                                 CXXRecordDecl *ClassBase);
  FunctionDecl *ValidateHookBase(FunctionDecl *H, FunctionDecl *B);

  FunctionDecl *FetchBaseOfHook(FunctionDecl *H, Expr *BaseExpr);
  TypeSourceInfo *AttachBaseToExtension(CXXRecordDecl *E, TypeSourceInfo *B);
};

/// Attribute handlers.

void handleLinkNameAttr(Sema &S, Decl *D, const ParsedAttr &AL);
void handleDynamicLinkageAttr(Sema &S, Decl *D, const ParsedAttr &AL);
void handleHookAttr(Sema &S, Decl *D, const ParsedAttr &AL);
void handleRecordExtensionAttr(Sema &S, Decl *D, const ParsedAttr &AL);
} // namespace clang

#endif // LLVM_CLANG_SEMA_ML_H