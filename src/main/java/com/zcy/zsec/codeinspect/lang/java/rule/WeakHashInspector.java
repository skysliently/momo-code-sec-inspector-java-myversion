package com.zcy.zsec.codeinspect.lang.java.rule;

import com.intellij.codeInspection.ProblemHighlightType;
import com.intellij.codeInspection.ProblemsHolder;
import com.intellij.psi.*;
import com.siyeh.ig.psiutils.MethodCallUtils;
import com.zcy.zsec.codeinspect.lang.InspectionBundle;
import com.zcy.zsec.codeinspect.lang.ZSecBaseLocalInspectionTool;
import com.zcy.zsec.codeinspect.lang.java.util.ZSecExpressionUtils;
import org.jetbrains.annotations.NotNull;

import java.util.HashSet;
import java.util.Set;

/**
 * 来自于momo安全检测插件
 *
 * MD2, MD4, MD5 为脆弱的消息摘要算法
 *
 * MD5的安全性受到严重损害。在4核2.6GHz的机器上，碰撞攻击可以在秒级完成。选择前缀碰撞攻击可以在小时级完成。
 *
 * ref:
 * https://en.wikipedia.org/wiki/MD5#Security
 *
 * 增加SHA1检测
 *
 */
public class WeakHashInspector extends ZSecBaseLocalInspectionTool {
    public static final String MESSAGE = InspectionBundle.message("weak.hash.inspector.msg");

    private static final Set<String> WeakHashNames = new HashSet<String>() {{
        add("MD2");
        add("MD4");
        add("MD5");
        add("SHA-1"); // 增加SHA1
        add("SHA1");
        add("SHA_1");
    }};

    @Override
    public @NotNull PsiElementVisitor buildVisitor(@NotNull ProblemsHolder holder, boolean isOnTheFly) {
        return new JavaElementVisitor() {
            @Override
            public void visitMethodCallExpression(PsiMethodCallExpression expression) {
                String methodCallName = MethodCallUtils.getMethodName(expression);

                PsiMethod method = expression.resolveMethod();
                if (method == null) { return ; }

                PsiClass containingClass = method.getContainingClass();
                if (containingClass == null) { return ; }

                String methodQualifiedName = containingClass.getQualifiedName();

                if ("java.security.MessageDigest".equals(methodQualifiedName) && "getInstance".equals(methodCallName)) {
                    checkZeroArgs(expression);
                } else if ("org.apache.commons.codec.digest.DigestUtils".equals(methodQualifiedName)) {
                    if ("getDigest".equals(methodCallName)) {
                        checkZeroArgs(expression);
                    } else if (
                            "getMd5Digest".equals(methodCallName) ||
                            "getMd2Digest".equals(methodCallName) ||
                            "md2".equals(methodCallName) ||
                            "md2Hex".equals(methodCallName) ||
                            "md5".equals(methodCallName) ||
                            "md5Hex".equals(methodCallName) ||
                            "sha".equals(methodCallName) ||
                            "shaHex".equals(methodCallName) ||
                            "getShaDigest".equals(methodCallName) ||
                            "sha1".equals(methodCallName) ||
                            "sha1Hex".equals(methodCallName) ||
                            "getSha1Digest".equals(methodCallName)
                    ) {
                        registerProblem(expression);
                    }
                }
            }

            @Override
            public void visitNewExpression(PsiNewExpression expression) {
                if (ZSecExpressionUtils.hasFullQualifiedName(expression, "org.apache.commons.codec.digest.DigestUtils")) {
                    checkZeroArgs(expression);
                }
            }

            private void checkZeroArgs(PsiCallExpression expression) {
                PsiExpressionList argList = expression.getArgumentList();
                if (argList == null) { return ; }
                PsiExpression[] args = argList.getExpressions();
                if (args.length > 0 && args[0] instanceof PsiLiteralExpression) {
                    String mdName = ZSecExpressionUtils.getLiteralInnerText(args[0]);
                    if (null != mdName && WeakHashNames.contains(mdName.toUpperCase())) {
                        registerProblem(expression);
                    }
                }
                else if (args.length > 0 && args[0] instanceof PsiReferenceExpression) {
                    String mdName = ((PsiReferenceExpression)args[0]).getReferenceNameElement().getText();
                    if (null != mdName && WeakHashNames.contains(mdName.toUpperCase())) {
                        registerProblem(expression);
                    }
                }
            }

            private void registerProblem(PsiExpression expression) {
                holder.registerProblem(expression, MESSAGE, ProblemHighlightType.GENERIC_ERROR_OR_WARNING);
            }
        };
    }
}
