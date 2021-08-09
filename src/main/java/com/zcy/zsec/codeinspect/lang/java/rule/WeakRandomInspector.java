package com.zcy.zsec.codeinspect.lang.java.rule;

import com.intellij.codeInspection.ProblemHighlightType;
import com.intellij.codeInspection.ProblemsHolder;
import com.intellij.psi.*;
import com.zcy.zsec.codeinspect.lang.InspectionBundle;
import com.zcy.zsec.codeinspect.lang.ZSecBaseLocalInspectionTool;
import com.zcy.zsec.codeinspect.lang.java.util.ZSecExpressionUtils;
import org.jetbrains.annotations.NotNull;

import java.util.regex.Pattern;

/**
 * 弱随机数检测 已存在实现插件
 */
public class WeakRandomInspector extends ZSecBaseLocalInspectionTool {
    public static final String MESSAGE = InspectionBundle.message("weak.random.msg");
    private static final Pattern weakRandomPattern = Pattern.compile("new Random\\s*\\(|Random\\.next", Pattern.CASE_INSENSITIVE);
    private static final Pattern weakRandomPackagePattern = Pattern.compile("((java|scala)\\.util\\.Random)", Pattern.CASE_INSENSITIVE);


    @Override
    public @NotNull PsiElementVisitor buildVisitor(@NotNull ProblemsHolder holder, boolean isOnTheFly) {
        return new JavaElementVisitor() {
            @Override
            public void visitNewExpression(PsiNewExpression expression) {
                if (ZSecExpressionUtils.hasFullQualifiedName(expression, "java.util.Random")
                        || ZSecExpressionUtils.hasFullQualifiedName(expression, "scala.util.Random")
                )
                    holder.registerProblem(
                            expression,
                            MESSAGE,
                            ProblemHighlightType.GENERIC_ERROR_OR_WARNING
                    );
            }

            @Override
            public void visitMethodCallExpression(PsiMethodCallExpression expression) {
                super.visitMethodCallExpression(expression);
            }

//            import检测暂未找到方法
            @Override
            public void visitImportList(PsiImportList list) {
//                visitElement(list);
                System.out.println(4);
//                list.getAllImportStatements()
            }

            @Override
            public void visitImportStatement(PsiImportStatement statement) {
//                super.visitImportStatement(statement);
                System.out.println(5);
            }

            @Override
            public void visitImportStaticReferenceElement(PsiImportStaticReferenceElement reference) {
//                super.visitImportStaticReferenceElement(reference);
                System.out.println(9);
            }
        };
    }
}
