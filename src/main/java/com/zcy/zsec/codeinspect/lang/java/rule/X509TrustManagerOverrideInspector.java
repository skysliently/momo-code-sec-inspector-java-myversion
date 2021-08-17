package com.zcy.zsec.codeinspect.lang.java.rule;

import com.intellij.codeInspection.ProblemHighlightType;
import com.intellij.codeInspection.ProblemsHolder;
import com.intellij.psi.*;
import com.zcy.zsec.codeinspect.lang.InspectionBundle;
import com.zcy.zsec.codeinspect.lang.ZSecBaseLocalInspectionTool;
import org.jetbrains.annotations.NotNull;

import java.util.Objects;

/**
 * 证书信任检测，规则来源于cobra
 * https://github.com/FeeiCN/Cobra
 */
public class X509TrustManagerOverrideInspector extends ZSecBaseLocalInspectionTool {
    public static final String MESSAGE = InspectionBundle.message("credential.trust.override.msg");

    @Override
    public @NotNull PsiElementVisitor buildVisitor(@NotNull ProblemsHolder holder, boolean isOnTheFly) {
        return new JavaElementVisitor() {
            @Override
            public void visitMethod(PsiMethod method) {
                if (method.getParameters().length == 0 && method.getAnnotations().length > 0){
                    if (method.getName().equals("getAcceptedIssuers")){
                        for (PsiAnnotation psiAnnotation :method.getAnnotations()) {
                            if (Objects.equals(psiAnnotation.getQualifiedName(), "java.lang.Override")) {
                                if (Objects.requireNonNull(method.getReturnType()).getCanonicalText().equals("java.security.cert.X509Certificate[]")) {
                                    holder.registerProblem(method, MESSAGE, ProblemHighlightType.GENERIC_ERROR_OR_WARNING);
                                }
                                break;
                            }
                        }
                    }
                }
            }

//            @Override
//            public void visitImportList(PsiImportList list) {
//                super.visitImportList(list);
//                System.out.println(0);
//                PsiImportStatementBase[] psiImportStatementBases = list.getAllImportStatements();
//                list.getAllImportStatements()[0].getImportReference().getText();
//            }
        };
    }
}
