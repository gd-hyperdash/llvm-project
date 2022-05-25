//===--------------------- SemaML.cpp - Sema ML extensions ----------------===//
//
// See ML_LICENSE.txt for license information.
//
//===----------------------------------------------------------------------===//

#include "clang/AST/DeclFriend.h"
#include "clang/Lex/Preprocessor.h"
#include "clang/Sema/Lookup.h"
#include "clang/Sema/ML.h"
#include "clang/Sema/SemaInternal.h"

using namespace clang;

//===----------------------------------------------------------------------===//
// Types
//===----------------------------------------------------------------------===//

struct ExtImpl {
  NamespaceDecl *NS = nullptr;
  ClassTemplateDecl *Impl = nullptr;

  explicit ExtImpl() = default;

  operator bool() const { return NS && Impl; }
};

//===----------------------------------------------------------------------===//
// Globals
//===----------------------------------------------------------------------===//

constexpr static auto ML_NS = "mlrt";
constexpr static auto ML_EXT_DATA = "_ExtImpl";
constexpr static auto ML_SELF = "_SelfFromHookImpl";
constexpr static auto ML_SELF_MUT = "_MutSelfFromHookImpl";
constexpr static auto ML_DEFAULT_DTOR_HOOK = "_DefaultDtorHook";

//===----------------------------------------------------------------------===//
// Helpers
//===----------------------------------------------------------------------===//

static Expr *UnwrapHookExpr(Expr *E) {
  if (auto UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UnaryOperatorKind::UO_AddrOf) {
      return UO->getSubExpr();
    }
  }

  return E;
}

static bool CheckHookBase(Sema &S, FunctionDecl const *H,
                          FunctionDecl const *FD) {
  if (!H || !FD)
    return false;

  auto HTy = H->getType()->getAs<FunctionProtoType>();
  auto FDTy = FD->getType()->getAs<FunctionProtoType>();
  assert(HTy && FDTy && "No type?");

  if (HTy->getReturnType().getCanonicalType() !=
      FDTy->getReturnType().getCanonicalType()) {
    S.Diag(H->getReturnTypeSourceRange().getBegin(), diag::err_hook_type)
        << FDTy->getReturnType().getAsString();
    return false;
  }

  if (HTy->getNumParams() != FDTy->getNumParams()) {
    auto Loc = HTy->getNumParams() ? H->getParametersSourceRange().getBegin()
                                   : H->getLocation();
    S.Diag(Loc, diag::err_hook_num_args);
    return false;
  }

  if (HTy->isVariadic() != FDTy->isVariadic()) {
    auto Loc = HTy->isVariadic() ? H->getEllipsisLoc() : H->getLocation();
    S.Diag(Loc, diag::err_hook_variadic);
    return false;
  }

  if (HTy->hasNoexceptExceptionSpec() != FDTy->hasNoexceptExceptionSpec()) {
    auto Loc = HTy->hasNoexceptExceptionSpec()
                   ? H->getExceptionSpecSourceRange().getBegin()
                   : H->getLocation();
    S.Diag(Loc, diag::err_hook_noexcept);
    return false;
  }

  for (auto i = 0u; i < HTy->getNumParams(); ++i) {
    if (HTy->getParamType(i).getCanonicalType() !=
        FDTy->getParamType(i).getCanonicalType()) {
      S.Diag(H->getParamDecl(i)->getTypeSpecStartLoc(), diag::err_hook_type)
          << FDTy->getParamType(i).getAsString();
      return false;
    }
  }

  return true;
}

static QualType GetHookType(Sema &S, FunctionDecl *H, CXXRecordDecl *Base) {
  QualType T = H->getType();

  if (!T.isNull()) {
    // Remove potential record qualifier.
    T = S.ExtractUnqualifiedFunctionType(T);

    // Member lookup requires the base qualifier.
    auto M = dyn_cast<CXXMethodDecl>(H);
    if (M && !M->isStatic()) {
      T = S.Context.getMemberPointerType(
          T, S.Context.getRecordType(Base).getTypePtr());
    }
  }

  return T;
}

// TODO: There's probably a better way to do this
static ExtImpl const FindExtensionImpl(TranslationUnitDecl *TU) {
  ExtImpl S;

  for (auto D : TU->decls()) {
    auto NS = dyn_cast<NamespaceDecl>(D);
    if (!NS || NS->getQualifiedNameAsString() != ML_NS)
      continue;

    for (auto R : NS->decls()) {
      auto Impl = dyn_cast<ClassTemplateDecl>(R);
      if (Impl && Impl->getName() == ML_EXT_DATA) {
        S.NS = NS;
        S.Impl = Impl;
        break;
      }
    }
  }

  return S;
}

bool InsertFriend(Sema &S, CXXRecordDecl *Base, CXXRecordDecl *Friend) {
  auto Ty = S.Context.getTrivialTypeSourceInfo(S.Context.getRecordType(Friend));

  if (Ty) {
    return FriendDecl::Create(S.Context, Base, Base->getLocation(),
                              FriendDecl::FriendUnion(Ty), SourceLocation());
  }

  return false;
}

static ClassTemplateSpecializationDecl *
CreateClassTS(Sema &S, ClassTemplateDecl *CTD,
              llvm::ArrayRef<TemplateArgument> Args) {
  void *IP = nullptr;

  if (!CTD || Args.empty()) {
    return nullptr;
  }

  auto Spec = CTD->findSpecialization(Args, IP);

  if (!Spec) {
    Spec = ClassTemplateSpecializationDecl::Create(
        S.Context, CTD->getTemplatedDecl()->getTagKind(), CTD->getDeclContext(),
        CTD->getTemplatedDecl()->getBeginLoc(), CTD->getLocation(), CTD, Args,
        nullptr);
    CTD->AddSpecialization(Spec, IP);
  }

  return Spec;
}

static ClassTemplateSpecializationDecl *GetClassTS(CXXRecordDecl *R) {
  return dyn_cast<ClassTemplateSpecializationDecl>(R);
}

static QualType GetClassTSType(Sema &S, ClassTemplateSpecializationDecl *Spec) {
  if (Spec) {
    return S.Context.getTemplateSpecializationType(
        TemplateName(Spec->getSpecializedTemplate()),
        Spec->getTemplateArgs().asArray(), S.Context.getRecordType(Spec));
  }

  return QualType();
}

static bool ForceCompleteClassTS(Sema &S,
                                 ClassTemplateSpecializationDecl *Spec) {
  auto T = GetClassTSType(S, Spec);
  return !T.isNull() ? S.isCompleteType(Spec->getLocation(), T) : false;
}

static bool ForceCompleteFunction(Sema &S, FunctionDecl *FD) {
  llvm::SmallPtrSet<const Type *, 4> Types;

  Types.insert(FD->getReturnType().getTypePtr());

  for (auto P : FD->parameters()) {
    Types.insert(P->getOriginalType().getTypePtr());
  }

  for (auto Ty : Types) {
    assert(Ty && "Type was nullptr!");
    if (auto TST = Ty->getAs<TemplateSpecializationType>()) {
      auto Spec = cast<ClassTemplateSpecializationDecl>(Ty->getAsRecordDecl());
      if (!ForceCompleteClassTS(S, Spec)) {
        return false;
      }
    }
  }

  return true;
}

NestedNameSpecifierLoc BuildRecordQualifier(Sema &S, RecordDecl *R,
                                            SourceRange Range = SourceRange()) {
  NestedNameSpecifierLocBuilder Builder;
  auto &Context = S.Context;

  auto NNS = NestedNameSpecifier::Create(Context, nullptr, false,
                                         Context.getRecordType(R).getTypePtr());

  Builder.MakeTrivial(Context, NNS, Range);
  return Builder.getWithLocInContext(Context);
}

UnaryOperator *BuildAddrOf(Sema &S, Expr *E,
                           SourceLocation Loc = SourceLocation()) {
  if (E) {
    auto UO = S.CreateBuiltinUnaryOp(Loc, UnaryOperatorKind::UO_AddrOf, E);
    return UO.isUsable() ? cast<UnaryOperator>(UO.get()) : nullptr;
  }

  return nullptr;
}

//===----------------------------------------------------------------------===//
// SemaML
//===----------------------------------------------------------------------===//

ASTContext &SemaML::GetContext() { return S.Context; }

IdentifierInfo *SemaML::GetIdentifier(StringRef Name) {
  return &S.PP.getIdentifierTable().get(Name);
}

bool SemaML::IsMLNamespace(const DeclContext *DC) {
  if (!DC) {
    return false;
  }

  if (auto ND = dyn_cast<NamespaceDecl>(DC)) {
    if (!ND->isInline() &&
        DC->getParent()->getRedeclContext()->isTranslationUnit()) {
      const IdentifierInfo *II = ND->getIdentifier();
      return II && II->isStr(ML_NS);
    }
  }

  return IsMLNamespace(DC->getParent());
}

bool SemaML::IsInMLNamespace(const Decl *D) {
  return D ? IsMLNamespace(D->getDeclContext()) : false;
}

DeclarationNameInfo SemaML::BuildDNI(const IdentifierInfo *II,
                                     SourceLocation Loc) {
  UnqualifiedId Id;
  TemplateArgumentListInfo TemplateArgsBuffer;
  const TemplateArgumentListInfo *TemplateArgs;
  DeclarationNameInfo NameInfo;

  Id.setIdentifier(II, Loc);
  S.DecomposeUnqualifiedId(Id, TemplateArgsBuffer, NameInfo, TemplateArgs);

  return NameInfo;
}

bool SemaML::InjectSuperKW(CXXRecordDecl *E, TypeSourceInfo *B) {
  const IdentifierInfo *II = GetIdentifier("super");
  auto NameInfo = BuildDNI(II, SourceLocation());
  auto Field = S.CheckFieldDecl(
      NameInfo.getName(),
      S.Context.getConstType(S.Context.getPointerType(B->getType())), B, E,
      SourceLocation(), false, nullptr, ICIS_CopyInit, SourceLocation(),
      AccessSpecifier::AS_public, nullptr, nullptr);
  if (Field) {
    auto NullPtr = S.ActOnCXXNullPtrLiteral(SourceLocation());
    assert(NullPtr.isUsable() && "No nullptr?");
    Field->setInClassInitializer(NullPtr.get());
    E->addDecl(Field);
    return true;
  }

  return false;
}

bool SemaML::IsInHookScope() {
  if (auto Scope = S.getCurScope()) {
    if (auto FnScope = Scope->getFnParent()) {
      auto Fn = cast_or_null<FunctionDecl>(FnScope->getEntity());
      return Fn && Fn->hasAttr<HookAttr>();
    }
  }

  return false;
}

ExprResult SemaML::LookupHookBaseImpl(CXXRecordDecl *Base, LookupResult &R) {
  DeclarationNameInfo DNI = R.getLookupNameInfo();

  // Find all matching bases.
  if (!S.LookupQualifiedName(R, Base))
    return ExprError();

  // Handle the lookup result.
  auto &Unresolved = R.asUnresolvedSet();

  if (Unresolved.size()) {
    auto Q = BuildRecordQualifier(S, Base);

    if (Unresolved.size() == 1u) {
      if (auto M = dyn_cast<CXXMethodDecl>(*Unresolved.begin())) {
        auto DeclRef = S.BuildDeclRefExpr(
            M, M->getType(), ExprValueKind::VK_PRValue, M->getNameInfo(), Q);
        return BuildAddrOf(S, DeclRef, DNI.getLoc());
      }
    } else {
      auto ULE = S.CreateUnresolvedLookupExpr(Base, Q, DNI, Unresolved, false);

      if (ULE.isUsable()) {
        return BuildAddrOf(S, ULE.get(), DNI.getLoc());
      }
    }
  }

  return ExprError();
}

CXXMethodDecl *SemaML::LookupBuiltinImpl(CXXRecordDecl *E,
                                         const IdentifierInfo *II,
                                         SourceLocation Loc) {
  DeclarationNameInfo NameInfo = BuildDNI(II, Loc);

  // Perform lookup.
  LookupResult R(S, NameInfo, Sema::LookupNameKind::LookupMemberName);

  if (S.LookupQualifiedName(R, E)) {
    auto Result = R.getAsSingle<CXXMethodDecl>();
    if (IsInMLNamespace(Result))
      return Result;
  }

  return nullptr;
}

ExprResult SemaML::LookupHookMemberBase(CXXRecordDecl *Base,
                                        const DeclarationNameInfo &DNI) {
  LookupResult R(S, DNI, Sema::LookupNameKind::LookupMemberName);
  return LookupHookBaseImpl(Base, R);
}

ExprResult SemaML::LookupHookDtorBase(CXXRecordDecl *Base) {
  if (auto Dtor = Base->getDestructor()) {
    LookupResult R(S, Dtor->getNameInfo(),
                   Sema::LookupNameKind::LookupDestructorName);
    return LookupHookBaseImpl(Base, R);
  }

  return ExprError();
}

CXXMethodDecl *SemaML::LookupBuiltinSelf(CXXRecordDecl *E, SourceLocation Loc,
                                         bool Mutable) {
  const IdentifierInfo *II = GetIdentifier(Mutable ? ML_SELF_MUT : ML_SELF);
  return LookupBuiltinImpl(E, II, Loc);
}

CXXMethodDecl *SemaML::LookupBuiltinDtorHook(CXXRecordDecl *MD) {
  const IdentifierInfo *II = GetIdentifier(ML_DEFAULT_DTOR_HOOK);
  return S.ML.LookupBuiltinImpl(MD, II, SourceLocation());
}

SemaML::HookBaseKind SemaML::GetHookBaseKind(Expr *BaseExpr) {
  if (isa<DeclRefExpr>(BaseExpr)) {
    return HookBaseKind::Simple;
  }

  if (isa<UnresolvedLookupExpr>(BaseExpr)) {
    return HookBaseKind::Lookup;
  }

  return HookBaseKind::Unknown;
}

FunctionDecl *SemaML::HandleSimpleBase(FunctionDecl *H, Expr *BaseExpr) {
  FunctionDecl *FD = nullptr;
  auto DRE = cast<DeclRefExpr>(BaseExpr);

  if (auto Fn = dyn_cast<FunctionDecl>(DRE->getDecl())) {
    FD = Fn;
  }

  if (!FD) {
    S.Diag(H->getLocation(), diag::err_hook_argument_not_valid);
    return nullptr;
  }

  return CheckHookBase(S, H, FD) ? FD : nullptr;
}

FunctionDecl *SemaML::HandleLookupBase(FunctionDecl *H, Expr *BaseExpr,
                                       CXXRecordDecl *ClassBase) {
  DeclAccessPair P;
  FunctionDecl *FD = nullptr;
  auto DT = GetHookType(S, H, ClassBase);

  if (!DT.isNull()) {
    FD = S.ResolveAddressOfOverloadedFunction(BaseExpr, DT, true, P);
  }

  if (!FD) {
    S.Diag(H->getLocation(), diag::err_hook_argument_not_valid);
  }

  return FD;
}

FunctionDecl *SemaML::ValidateHookBase(FunctionDecl *H, FunctionDecl *B) {
  if (!H || !B) {
    return nullptr;
  }

  // Hooks cannot hook other hooks.
  if (B->hasAttr<HookAttr>()) {
    S.Diag(H->getLocation(), diag::err_hook_argument_is_hook);
    return nullptr;
  }

  if (auto BaseMethod = dyn_cast<CXXMethodDecl>(B)) {
    auto HookMethod = dyn_cast<CXXMethodDecl>(H);
    auto HookParent = HookMethod ? HookMethod->getParent() : nullptr;

    // Methods can only be hooked in the context of an extension.
    if (!HookMethod || !HookParent->hasAttr<RecordExtensionAttr>()) {
      S.Diag(H->getLocation(), diag::err_hook_argument_not_valid);
      return nullptr;
    }

    // Method base and extension base must match.
    auto ExtBase = HookParent->getAttr<RecordExtensionAttr>()
                       ->getBase()
                       ->getAsCXXRecordDecl();
    assert(ExtBase && "No base?");

    if (ExtBase != BaseMethod->getParent()) {
      S.Diag(H->getLocation(), diag::err_hook_member_base)
          << BaseMethod->getParent()->getQualifiedNameAsString();
      return nullptr;
    }

    // Method hooks cannot be virtual.
    if (HookMethod->isVirtual()) {
      S.Diag(H->getLocation(), diag::err_hook_virtual);
      return nullptr;
    }
  }

  // Complete base type when needed.
  if (!ForceCompleteFunction(S, B)) {
    S.Diag(B->getLocation(), diag::err_hook_argument_not_valid);
    return nullptr;
  }

  return B;
}

FunctionDecl *SemaML::FetchBaseOfHook(FunctionDecl *H, Expr *BaseExpr) {
  FunctionDecl *FD = nullptr;
  CXXRecordDecl *ClassBase = nullptr;

  // Unwrap the expression.
  auto UnwrappedExpr = UnwrapHookExpr(BaseExpr);

  // Get class base, if any.
  if (auto M = dyn_cast<CXXMethodDecl>(H)) {
    auto P = M->getParent();

    if (auto RE = P->getAttr<RecordExtensionAttr>()) {
      ClassBase = RE->getBase()->getAsCXXRecordDecl();
    }
  }

  // Handle base.
  switch (GetHookBaseKind(UnwrappedExpr)) {
  case HookBaseKind::Simple:
    FD = HandleSimpleBase(H, UnwrappedExpr);
    break;
  case HookBaseKind::Lookup:
    FD = HandleLookupBase(H, BaseExpr, ClassBase);
    break;
  default:;
  }

  // Inherit CC.
  if (FD) {
    auto BTy = FD->getType()->getAs<FunctionProtoType>();
    auto HTy = H->getType()->getAs<FunctionProtoType>();
    auto EPI = HTy->getExtProtoInfo();
    EPI.ExtInfo = EPI.ExtInfo.withCallingConv(BTy->getCallConv());
    H->setType(S.Context.getFunctionType(HTy->getReturnType(),
                                         HTy->getParamTypes(), EPI));
  }

  return ValidateHookBase(H, FD);
}

FunctionDecl *SemaML::LookupBaseOfHook(FunctionDecl *H) {
  if (auto M = dyn_cast<CXXMethodDecl>(H)) {
    if (auto Attr = M->getParent()->getAttr<RecordExtensionAttr>()) {
      auto Class = Attr->getBase()->getAsCXXRecordDecl();
      assert(Class && "No base?");
      auto Expr = LookupHookMemberBase(Class, M->getNameInfo());
      if (Expr.isUsable()) {
        return FetchBaseOfHook(H, Expr.get());
      }
    }
  }

  S.Diag(H->getLocation(), diag::err_hook_argument_not_valid);
  return nullptr;
}

TypeSourceInfo *SemaML::AttachBaseToExtension(CXXRecordDecl *E,
                                              TypeSourceInfo *B) {
  auto &Context = GetContext();
  auto TU = Context.getTranslationUnitDecl();
  auto Data = FindExtensionImpl(TU);

  if (!Data) {
    return nullptr;
  }

  // Get base.
  QualType BaseType = B->getType();
  assert(!BaseType.isNull() && "No type?");
  assert(!BaseType->isDependentType() && "Dependant type not allowed!");
  auto Base = BaseType->getAsCXXRecordDecl();
  assert(Base && "Base was nullptr!");

  // If the base is a specialization, make sure it's fully instantiated.
  if (auto Spec = GetClassTS(Base)) {
    if (!ForceCompleteClassTS(S, Spec)) {
      return nullptr;
    }
  }

  // Instantiate ML base.
  TemplateArgument ExtArg(Context.getRecordType(E));
  TemplateArgument BaseArg(BaseType.getCanonicalType());
  auto TemplateArgs =
      TemplateArgumentList::CreateCopy(Context, {ExtArg, BaseArg});
  auto Spec = CreateClassTS(S, Data.Impl, TemplateArgs->asArray());
  auto SpecTy = GetClassTSType(S, Spec);

  // Get ML base type.
  auto NNS = NestedNameSpecifier::Create(Context, nullptr, Data.NS);
  auto SpecElaborated =
      Context.getElaboratedType(ElaboratedTypeKeyword::ETK_None, NNS, SpecTy);
  auto SpecInfo =
      Context.getTrivialTypeSourceInfo(SpecElaborated, E->getLocation());

  // Inherit ML base.
  auto Specifier =
      S.CheckBaseSpecifier(E, SourceRange(), false, AccessSpecifier::AS_public,
                           SpecInfo, SourceLocation());

  if (Specifier && !S.AttachBaseSpecifiers(E, {Specifier}) &&
      InsertFriend(S, Base, E) && InsertFriend(S, E, Spec) &&
      InsertFriend(S, Base, Spec) && InjectSuperKW(E, B)) {
    E->addAttr(FinalAttr::Create(S.Context, SourceLocation(),
                                 AttributeCommonInfo::AS_Keyword,
                                 FinalAttr::Spelling::Keyword_final));
    return Context.getTrivialTypeSourceInfo(Context.getRecordType(Base));
  }

  return nullptr;
}

//===----------------------------------------------------------------------===//
// Attribute Handlers
//===----------------------------------------------------------------------===//

void clang::handleDynamicLinkageAttr(Sema &S, Decl *D, const ParsedAttr &AL) {
  // Prevent dynamic methods.
  if (auto const M = dyn_cast<CXXMethodDecl>(D)) {
    S.Diag(AL.getLoc(), diag::err_dynamic_method);
    S.Diag(AL.getLoc(), diag::note_dynamic_mark_record)
        << M->getParent()->getKindName();
    return;
  }

  if (auto const FD = dyn_cast<FunctionDecl>(D)) {
    // Prevent entrypoint.
    if (FD->isMain()) {
      S.Diag(AL.getLoc(), diag::err_dynamic_main);
      return;
    }
  }

  // Add attribute.
  D->addAttr(::new (S.Context) DynamicLinkageAttr(S.Context, AL));
}

void clang::handleHookAttr(Sema &S, Decl *D, const ParsedAttr &AL) {
  auto FD = cast<FunctionDecl>(D);

  // A hook can only target one function.
  if (FD->hasAttr<HookAttr>()) {
    S.Diag(AL.getLoc(), diag::err_hook_already_marked);
    return;
  }

  // Prevent setting entrypoint as a hook.
  if (FD->isMain()) {
    S.Diag(AL.getLoc(), diag::err_hook_main);
    return;
  }

  // Parse base.
  FunctionDecl *HookBase = nullptr;
  bool HasBase = false;
  if (AL.getNumArgs() > 0) {
    S.getDiagnostics().setSuppressAllDiagnostics(true);
    HookBase = S.ML.FetchBaseOfHook(FD, AL.getArgAsExpr(0));
    S.getDiagnostics().setSuppressAllDiagnostics(false);
    HasBase = HookBase != nullptr;
  }

  if (!HookBase) {
    HookBase = S.ML.LookupBaseOfHook(FD);
    if (!HookBase)
      return;
  }

  // Parse flags.
  SmallVector<unsigned, 8> Flags;
  bool FlagError = false;
  for (auto i = HasBase ? 1u : 0u; i < AL.getNumArgs(); ++i) {
    Expr::EvalResult Result = {};
    auto E = AL.getArgAsExpr(i);
    if (E->EvaluateAsInt(Result, S.Context)) {
      Flags.push_back(Result.Val.getInt().getZExtValue());
    } else {
      S.Diag(E->getExprLoc(), diag::err_hook_flag);
      FlagError = true;
    }
  }

  // Add attribute.
  if (!FlagError) {
    D->addAttr(::new (S.Context) HookAttr(S.Context, AL, HookBase, Flags.data(),
                                          Flags.size()));
    S.ML.AddSillyAttr<HookBaseAttr>(HookBase);
  }
}

void clang::handleRecordExtensionAttr(Sema &S, Decl *D, const ParsedAttr &AL) {
  TypeSourceInfo *TSI = nullptr;
  auto E = cast<CXXRecordDecl>(D);
  assert(AL.hasParsedType() && "No type?");

  // Get base type.
  auto T = S.GetTypeFromParser(AL.getTypeArg(), &TSI);

  if (!TSI) {
    TSI = S.Context.getTrivialTypeSourceInfo(T, AL.getLoc());
  }

  assert(TSI && "Type was nullptr!");

  // We do not accept dependant types.
  if (TSI->getType()->isDependentType()) {
    S.Diag(AL.getLoc(), diag::err_extension_argument_is_dependant);
    return;
  }

  // Add attribute.
  if (auto BaseType = S.ML.AttachBaseToExtension(E, TSI)) {
    D->addAttr(::new (S.Context) RecordExtensionAttr(S.Context, AL, BaseType));
  } else {
    S.Diag(AL.getLoc(), diag::err_extension_failed);
  }
}

void clang::handleNoDeallocatorAttr(Sema &S, Decl *D, const ParsedAttr &AL) {
  D->addAttr(::new (S.Context) NoDeallocatorAttr(S.Context, AL));
}