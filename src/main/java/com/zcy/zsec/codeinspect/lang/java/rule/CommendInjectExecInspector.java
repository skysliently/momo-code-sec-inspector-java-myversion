package com.zcy.zsec.codeinspect.lang.java.rule;

import com.intellij.codeInspection.ProblemHighlightType;
import com.intellij.codeInspection.ProblemsHolder;
import com.intellij.psi.JavaElementVisitor;
import com.intellij.psi.PsiElementVisitor;
import com.intellij.psi.PsiMethodCallExpression;
import com.intellij.psi.PsiNewExpression;
import com.zcy.zsec.codeinspect.lang.InspectionBundle;
import com.zcy.zsec.codeinspect.lang.ZSecBaseLocalInspectionTool;
import com.zcy.zsec.codeinspect.lang.java.util.ZSecExpressionUtils;
import org.jetbrains.annotations.NotNull;

/**
 * 命令执行检测提示插件
 *
 * 1. java.lang.Runtime.exec
 * 2. java.lang.ProcessBuilder.start
 * 3. javax.script.ScriptEngineManager  eval
 *
 */
public class CommendInjectExecInspector extends ZSecBaseLocalInspectionTool {
    public static final String MESSAGE = InspectionBundle.message("commend.injection.exec.msg");

    @Override
    public @NotNull PsiElementVisitor buildVisitor(@NotNull ProblemsHolder holder, boolean isOnTheFly) {
        return new JavaElementVisitor() {
            @Override
            public void visitMethodCallExpression(PsiMethodCallExpression expression) {
                if (
                        ZSecExpressionUtils.hasFullQualifiedName(expression, "java.lang.Runtime", "getRuntime")
                        || ZSecExpressionUtils.hasFullQualifiedName(expression, "java.lang.Runtime", "exec")
                        || ZSecExpressionUtils.hasFullQualifiedName(expression, "javax.script.ScriptEngine", "eval")
                )
                    holder.registerProblem(expression, MESSAGE, ProblemHighlightType.GENERIC_ERROR_OR_WARNING);
            }

            @Override
            public void visitNewExpression(PsiNewExpression expression) {
                if (ZSecExpressionUtils.hasFullQualifiedName(expression, "java.lang.ProcessBuilder"))
                    holder.registerProblem(expression, MESSAGE, ProblemHighlightType.GENERIC_ERROR_OR_WARNING);
            }
        };
    }
}
