# PXPanel v15.0.0 — Professional UI

## UI
- تم دارک اصلی (شبیه داشبورد متریکس حرفه‌ای)
- تم لایت کامل
- بدون box-shadow
- سایدبار چپ
- کارت‌های متریکس + چارت

## Templates
```
templates/dashboard/  index.html · style.css · app.js
templates/login/
templates/setup/
static/...            (سرو شده توسط FastAPI)
```

## سیستم کانفیگ
منطق ساخت/حذف/ساب/پروتکل‌ها دست‌نخورده است.

## ربات تلگرام
- ربات اصلی پنل (توکن + ادمین + webhook)
- **ربات کاربران:** بخش جدا در داشبورد → ثبت توکن ربات هر کاربر برای ساخت خودکار کانفیگ

## API جدید
- `GET/POST /api/telegram/user-bots`
- `DELETE /api/telegram/user-bots/{id}`

## نسخه
15.0.0 در همه جا
