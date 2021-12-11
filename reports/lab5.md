Цю роботу ми писали на C#, де є багато фреймворків для створення вланих додатків. Ми обрали ASP.NET, оскільки в ньому є багато вбудованих фіч.
Одною із таких фіч є сторінки, які пов'язані з користувачем, а саме регістрація, логін, інформація про користувача, усе це відразу є у Microsoft.AspNetCore.Identity Framework.
Звісно все це можна налаштувати, до прикладу вимоги до пароля із дефолтних можна змінити на якісь свої:
~~~
services.Configure<IdentityOptions>(options =>
{
    // Default Password settings.
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequiredLength = 6;
    options.Password.RequiredUniqueChars = 1;
});
~~~

Для зберігання ми обрали PostgreSQL, де створили БД. В ній зберігається багато даних сгернерованих Identity. 
Але основними із них є ім'я користувача та захешований пароль за допомогою Argon2i із сілью.
Під час входу ми беремо пароль та за допомогою вбудованої функції Argon2i запевнюємось, що це той пароль, який захешовано.
