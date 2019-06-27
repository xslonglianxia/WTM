//
// CookieAuthMiddleware.cs
//
// Author:
//       Vito <wuwenhao0327@gmail.com>
//
// Copyright (c) 2019 Vito
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
using System;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

using WalkingTec.Mvvm.Core;

namespace WalkingTec.Mvvm.Mvc.Auth
{
    public class CookieAuthMiddleware : IMiddleware
    {
        protected static string[] _publicUrls;

        public CookieAuthMiddleware()
        {
            if (_publicUrls == null)
            {
                var res = GlobalServices.GetRequiredService<GlobalData>().AllPublicUrls;
                _publicUrls = new string[res.Length];
                for (int i = 0; i < res.Length; i++)
                {
                    _publicUrls[i] = "/" + res[i].ToLower();
                }
            }
        }

        public async Task InvokeAsync(HttpContext context, RequestDelegate next)
        {
            // 过滤不需要的登录的 url
            if (_publicUrls.Contains(context.Request.Path.Value.ToLower())) // 不需要登录
            {
                await next.Invoke(context);
            }
            else // 需要登录
            {
                var loginUserInfo = context?.Session?.Get<LoginUserInfo>("UserInfo");
                if (loginUserInfo == null || Guid.Empty == loginUserInfo.Id)// 未登录
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    context.Response.ContentType = "text/html";
                    await context.Response.WriteAsync($"<script>window.location.href = '/Login/Login?rd={HttpUtility.UrlEncode(context.Request.Path)}'</script>");
                }
                else
                {
                    await next.Invoke(context);
                }
            }
        }
    }

    public static class CookieAuthMiddlewareExtensions
    {
        public static IApplicationBuilder UseCookieAuth(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<CookieAuthMiddleware>();
        }
    }
}
