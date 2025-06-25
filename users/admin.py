from django.contrib import admin
from .models import Message, School, GraduationYear, CustomUser, Note
from django import forms


@admin.register(School)
class SchoolAdmin(admin.ModelAdmin):
    list_display = ('name',)
    search_fields = ('name',)


@admin.register(GraduationYear)
class GraduationYearAdmin(admin.ModelAdmin):
    list_display = ('year',)  # Added school if it exists in your model
    ordering = ('-year',)
    fields = ('year',)  # Only show these fields in admin

    def save_model(self, request, obj, form, change):
        # If your model still has password field but it's not required
        if hasattr(obj, 'password') and not obj.password:
            obj.password = ''  # Set empty string if field exists
        super().save_model(request, obj, form, change)


@admin.register(CustomUser)
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('username', 'first_name', 'last_name', 'school', 'graduation_year')
    list_filter = ('school', 'graduation_year')
    search_fields = ('username', 'first_name', 'last_name')


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ('sender', 'receiver', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('sender__username', 'receiver__username', 'content')


@admin.register(Note)
class NoteAdmin(admin.ModelAdmin):
    list_display = ('sender', 'receiver', 'year', 'created_at')
    list_filter = ('year', 'created_at')
    search_fields = ('sender__username', 'receiver__username', 'content')