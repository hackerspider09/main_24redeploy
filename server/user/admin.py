from django.contrib import admin
from import_export.admin import ImportExportActionModelAdmin
from import_export import resources
from import_export import fields, resources
from .models import *

@admin.register(Event)
class EventAdmin(ImportExportActionModelAdmin):
    list_display = ("event_id", "event_name", "event_start", "event_end", "group_event")

@admin.register(User)
class UserAdmin(ImportExportActionModelAdmin):
    list_display = ("username", "full_name", "phone", "coins", "senior", "referral")
    search_fields = ("username", "phone")

@admin.register(Referral)
class ReferralAdmin(ImportExportActionModelAdmin):
    list_display = ("referrer", "referred_user", "timestamp", "referral_code")

class OrderResource(resources.ModelResource):
    user = fields.Field(attribute='user__full_name', column_name='Name')
    phone = fields.Field(attribute='user__phone', column_name='phone')
    event = fields.Field(attribute='event__event_name', column_name='event')
    email = fields.Field(attribute='user__email', column_name='email')
    order_date = fields.Field(attribute='order_date', column_name='order date')
    payment = fields.Field(attribute='payment', column_name='payment')
    transaction_id = fields.Field(attribute='transaction_id', column_name='transaction_id')

@admin.register(Order)
class OrderAdmin(ImportExportActionModelAdmin):
    resource_class = OrderResource
    raw_id_fields = ('event',)
    list_display = ('id', 'user', 'event', 'order_date', 'payment', 'transaction_id', 'phone', 'email')
    search_fields = ("user__username", "user__phone", "transaction_id", "event__event_name")

    def phone(self, obj):
        return obj.user.phone
    
    def email(self, obj):
        return obj.user.email
    
    def wallstreet_mail(self, request, queryset):
        event_name = 104 
        users_with_event = queryset.filter(event__event_name=event_name).values_list('user', flat=True).distinct()
        for user_id in users_with_event:
            print(user_id)
            # user = User.objects.get(id=user_id)

            # context = {"user": user, "team_id": new_team.team_id, "event": event_check, "team_password" : new_team.team_password}
            #     html_message = render_to_string("team.html", context=context)
            #     try:
            #         send_mail(
            #                 'Your Team',
            #                 '',
            #                 settings.EMAIL_HOST_USER,
            #                 [email],
            #                 html_message=html_message,
            #                 fail_silently=False,
            #             )
            #     except Exception as e:
            #         print(f"email failed due to: {e}")

            # subject = 'Wallstreet Update'
            # message = 'Body of your email'
            # from_email = 'your-email@example.com'
            # recipient_list = [user.email]
            # send_mail(subject, message, from_email, recipient_list)
        self.message_user(request, f'Mail sent to {len(users_with_event)} users with event {event_name}')

    wallstreet_mail.short_description = "Send mail to wallstreet users"

    actions = [wallstreet_mail]

    
class TeamResource(resources.ModelResource):
    event_name = fields.Field(attribute='event__event_name', column_name='Event Name')
    usernames = fields.Field()
    team_id  = fields.Field(attribute='team_id', column_name='Team ID')
    phones = fields.Field()
    emails = fields.Field()
    names = fields.Field()

    class Meta:
        model = Team
        fields = ('event_name', 'usernames', 'team_id')
    
    def dehydrate_usernames(self, team):
        return ", ".join([user.username for user in team.user.all()])
    
    def dehydrate_phones(self, team):
        return ", ".join([user.phone for user in team.user.all()])
    
    def dehydrate_emails(self, team):
        return ", ".join([user.email for user in team.user.all()])
    
    def dehydrate_names(self, team):
        return ", ".join([user.full_name for user in team.user.all()])

@admin.register(Team)
class TeamAdmin(ImportExportActionModelAdmin):
    resource_class = TeamResource
    list_display = ("event_name", "users", "team_id", "team_name", "team_password")
    search_fields = ("event__event_name", "user__username")
    list_filter = ('event',)

    def event_name(self, obj):
        if obj.event:
            return obj.event.event_name
        else:
            return 'NA'
    
    def users(self, obj):
        if obj.user:
            full_names = [f"{user.first_name} {user.last_name}" for user in obj.user.all()]
            return ", ".join(full_names)
        else:
            return 'NA'
        
class TransactionResource(resources.ModelResource):
    user_name = fields.Field(attribute='user__full_name', column_name='Full name')
    transaction_id = fields.Field(attribute='transaction_id', column_name='Transaction Id')
    order_date = fields.Field(attribute='order_date', column_name='Order Date')
    event_list = fields.Field(attribute='event_list', column_name='Event List')

    class Meta:
        model = Transaction
        fields = ('user_name', 'transaction_id', 'order_date', 'event_list')

@admin.register(Transaction)
class TransactionAdmin(ImportExportActionModelAdmin):
    resource_class = TransactionResource
    list_display = ("user_name", "transaction_id", "order_date", 'event_list', 'amount', 'payment')
    search_fields = ("user__username", "user__phone", "transaction_id")


    def user_name(self, obj):
        return obj.user
    
@admin.register(Feedback)
class FeedbackAdmin(admin.ModelAdmin):
    list_display = ('name', 'email', 'context')
