/**
 * 此插件无法检测类似与123456789这种呆逼密码
 */
package com.zcy.zsec.codeinspect.lang.java.rule;

import com.intellij.codeInspection.ProblemHighlightType;
import com.intellij.codeInspection.ProblemsHolder;
import com.intellij.psi.*;
import com.intellij.util.ObjectUtils;
import com.zcy.zsec.codeinspect.lang.InspectionBundle;
import com.zcy.zsec.codeinspect.lang.ZSecBaseLocalInspectionTool;
import com.zcy.zsec.codeinspect.lang.java.util.ZSecExpressionUtils;
import me.gosimple.nbvcxz.Nbvcxz;
import org.jetbrains.annotations.NotNull;

import java.util.regex.Pattern;

/**
 * Momo 1020: 硬编码凭证风险；原逻辑改编自gosec；增加了两种情况的检查
 *
 * ref:
 * (1) https://github.com/securego/gosec/blob/master/rules/hardcoded_credentials.go
 */
public class HardcodedCredentials extends ZSecBaseLocalInspectionTool {
    public static final String MESSAGE = InspectionBundle.message("hardcoded.credentials.msg");
//    private static final Pattern pattern = Pattern.compile("passwd|pass|password|pwd|secret|token", Pattern.CASE_INSENSITIVE);
    private static final Pattern pattern = Pattern.compile("passwd|pass|password|pwd|secret|token|pw|apiKey|bearer|cred", Pattern.CASE_INSENSITIVE);
    private static final Pattern connPwdPattern = Pattern.compile("password=(.*?)($|&)", Pattern.CASE_INSENSITIVE);
    private static final Pattern setMethodCallPattern = Pattern.compile(".\\.set.", Pattern.CASE_INSENSITIVE); //数据对象set方法匹配
    private static final double entropyThreshold = 50.0;
    private static final int truncate = 16;


    @Override
    public @NotNull PsiElementVisitor buildVisitor(@NotNull ProblemsHolder holder, boolean isOnTheFly) {
        return new JavaElementVisitor() {

            @Override
            public void visitLocalVariable(PsiLocalVariable variable) {
                String varname = variable.getName();
//                判断变量名是否涉及凭证信息
                if (varname != null && pattern.matcher(varname).find()) {
                    PsiExpression initializer = variable.getInitializer();
//                    判断初始化方法/方式是否是字符表达式
                    if (initializer instanceof PsiLiteralExpression) {
                        String value = ZSecExpressionUtils.getLiteralInnerText(initializer);
                        if (value != null && isHighEntropyString(value) && isASCII(value)) {
                            holder.registerProblem(variable, MESSAGE, ProblemHighlightType.GENERIC_ERROR_OR_WARNING);
                        }
                    }
                }
            }

//            赋值表达式
            @Override
            public void visitAssignmentExpression(PsiAssignmentExpression expression) {
                PsiExpression lexp = expression.getLExpression();
//                获取表达式左侧内容，判断是否是引用表达式类型
                if (lexp instanceof PsiReferenceExpression) {
                    String varname = ((PsiReferenceExpression) lexp).getQualifiedName();
//                    判断变量名是否涉及凭证信息
                    if (pattern.matcher(varname).find()) {
                        PsiExpression rexp = expression.getRExpression();
//                        判断右侧表达式是否是字符型表达式
                        if (rexp instanceof PsiLiteralExpression) {
                            String value = ZSecExpressionUtils.getLiteralInnerText(rexp);
                            if (value != null && isHighEntropyString(value) && isASCII(value)) {
                                holder.registerProblem(expression, MESSAGE, ProblemHighlightType.GENERIC_ERROR_OR_WARNING);
                            }
                        }
//                        对于new String进行单独处理
                        else if (rexp instanceof PsiNewExpression) {
                            checkNewString(expression, (PsiNewExpression) rexp, holder);
                        }
                    }
                }
            }

//            Java field or enum constant
            @Override
            public void visitField(PsiField field) {
                String varname = field.getName();
//                判断Field name是否涉及凭证信息
                if (varname != null && pattern.matcher(varname).find()) {
                    PsiExpression initializer = field.getInitializer();
//                    判断初始化方法/方式是否是字符表达式
                    if (initializer instanceof PsiLiteralExpression) {
                        String value = ZSecExpressionUtils.getLiteralInnerText(initializer);
                        if (value != null && isHighEntropyString(value) && isASCII(value)) {
                            holder.registerProblem(field, MESSAGE, ProblemHighlightType.GENERIC_ERROR_OR_WARNING);
                        }
                    }
                }
            }

            @Override
            public void visitMethodCallExpression(PsiMethodCallExpression expression) {
//                用于匹配Properties.put存入密码信息的方式（put是Hashtable的方法）
//                例如 properties.put("password", "the password 1 ");

//                Hashtable操作
//                判断expression是否是"put"方法
//                且expression（put方法）是否在"java.util.Hashtable"中
                if (ZSecExpressionUtils.hasFullQualifiedName(expression, "java.util.Hashtable", "put")) {
                    PsiExpression qualifierExp = expression.getMethodExpression().getQualifierExpression();
//                    判断类是否是Properties
                    if (qualifierExp != null &&
                            qualifierExp.getType() != null &&
                            "java.util.Properties".equals(qualifierExp.getType().getCanonicalText())
                    ) {
                        PsiExpression[] args = expression.getArgumentList().getExpressions();
                        if (args.length == 2 && args[1] instanceof PsiLiteralExpression) {
                            String key = ZSecExpressionUtils.getText(args[0], true);
                            if (key != null && pattern.matcher(key).find()) {
                                String value = ZSecExpressionUtils.getLiteralInnerText(args[1]);
                                if (value != null && isHighEntropyString(value) && isASCII(value)) {
                                    holder.registerProblem(expression, MESSAGE, ProblemHighlightType.GENERIC_ERROR_OR_WARNING);
                                }
                            }
                        }
                    }
//                JDBC 连接中的硬编码凭证
//                判断expression是否是"getConnection"或者是否在"java.sql.DriverManager"中
                } else if (ZSecExpressionUtils.hasFullQualifiedName(expression, "java.sql.DriverManager", "getConnection")) {
                    // 检查0位参的连接串，或3位参的password字段
                    PsiExpression[] args = expression.getArgumentList().getExpressions();
                    if (args.length == 1) {
                        String connUrl = ZSecExpressionUtils.getLiteralInnerText(ObjectUtils.tryCast(args[0], PsiLiteralExpression.class));
                        if (connUrl != null && connPwdPattern.matcher(connUrl).find()) {
                            holder.registerProblem(expression, MESSAGE, ProblemHighlightType.GENERIC_ERROR_OR_WARNING);
                        }
                    } else if (args.length == 3) {
                        PsiLiteralExpression password = ObjectUtils.tryCast(args[2], PsiLiteralExpression.class);
                        if (password != null) {
                            holder.registerProblem(expression, MESSAGE, ProblemHighlightType.GENERIC_ERROR_OR_WARNING);
                        }
                    }
                }
//                自定义数据类型进行set操作
                else if (setMethodCallPattern.matcher(expression.getMethodExpression().getText()).find()){
                    setMethodCallCheck(expression, holder);
                }
            }
        };
    }


    /**
     * 判断字符串复杂度，是否类似于密码
     * @param v String
     * @return boolean
     */
    private static boolean isHighEntropyString(String v) {
        if (truncate < v.length()) {
            v = v.substring(0, truncate);
        }
        return new Nbvcxz().estimate(v).getEntropy() > entropyThreshold;
    }

    /**
     * 判断该字符串是否以ASCII组成，常见凭证一般以ASCII组成
     * @param text String
     * @return boolean
     */
    private static boolean isASCII(String text){
        for(int i = 0, l=text.length(); i < l; i++) {
            if((int)text.charAt(i) > 128) {
                return false;
            }
        }
        return true;
    }

    /**
     * 对于new String进行额外单独校验
     * @param expression PsiAssignmentExpression
     * @param rexp PsiNewExpression
     * @param holder ProblemsHolder
     */
    private void checkNewString(PsiAssignmentExpression expression, PsiNewExpression rexp, @NotNull ProblemsHolder holder) {
        try {
            PsiExpression psiExpression = rexp.getArgumentList().getExpressions()[0];
            String innerText = ZSecExpressionUtils.getLiteralInnerText(psiExpression);
            if (innerText != null && isHighEntropyString(innerText) && isASCII(innerText)) {
                holder.registerProblem(expression, MESSAGE, ProblemHighlightType.GENERIC_ERROR_OR_WARNING);
            }
        } catch (Exception e) {
//            System.out.println(e);
//            return;
        }
    }

    /**
     * 对数据类set操作进行校验
     * @param expression PsiMethodCallExpression
     * @param holder ProblemsHolder
     */
    private void setMethodCallCheck(PsiMethodCallExpression expression, @NotNull ProblemsHolder holder) {
        if (pattern.matcher(expression.getMethodExpression().getLastChild().getText()).find()) {
            PsiExpression psiExpression = expression.getArgumentList().getExpressions()[0];
            String innerText = ZSecExpressionUtils.getLiteralInnerText(psiExpression);
            if (innerText != null && isHighEntropyString(innerText) && isASCII(innerText)) {
                holder.registerProblem(expression, MESSAGE, ProblemHighlightType.GENERIC_ERROR_OR_WARNING);
            }
        }
    }

}
