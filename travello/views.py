from django.shortcuts import render,redirect
from django.http import HttpResponse,HttpResponseRedirect
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.db import IntegrityError
from django.contrib.auth import login,authenticate,logout
from django.urls import reverse
from django.core.mail import send_mail
from django.conf import settings

from django.conf import settings
# Avoid shadowing the login() and logout() views below.
from django.contrib.auth import (
    REDIRECT_FIELD_NAME, get_user_model, login as auth_login,
    logout as auth_logout, update_session_auth_hash,
)
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import (
    AuthenticationForm, PasswordChangeForm, PasswordResetForm, SetPasswordForm,
)
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.exceptions import ValidationError
from django.http import HttpResponseRedirect, QueryDict
from django.shortcuts import resolve_url
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.utils.http import (
    url_has_allowed_host_and_scheme, urlsafe_base64_decode,
)
from django.utils.translation import gettext_lazy as _
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic.base import TemplateView
from django.views.generic.edit import FormView
from django.views.decorators.csrf import csrf_protect

import email, smtplib, ssl
from django.contrib.auth.models import User
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

UserModel = get_user_model()

# Create your views here.
def index(request):
    return render(request,'index.html')
def contact(request):
    return render(request,'contact.html')
def news(request):
    return render(request,'news.html')
def about(request):
    return render(request,'about.html')
def register(request):
    if request.method=='POST':
        if request.POST.get('password1') == request.POST.get('password2'):
            try:
                saveuser = User.objects.create_user(request.POST.get('username'),password = request.POST.get('password1'))
                saveuser.save()
                send_mail(
                "Eduglobal9 Registration Management System",
                'You have been successfully registered',
                settings.EMAIL_HOST_USER,
                [request.POST.get('email')]
                )
                return render(request,'register.html',{'form':UserCreationForm(),'info':'The user: '+request.POST.get('username')+' is saved successfully...'})
            except IntegrityError:
                  return render(request,'register.html',{'form':UserCreationForm(),'error':'The user: '+request.POST.get('username')+' already exists..'})
        else:
            return render(request,'register.html',{'form':UserCreationForm(),'error':'The passwords are not matching!!!'})
    else:
        return render(request,'register.html',{'form':UserCreationForm})
def signin(request):
    context={}
    if request.method=="POST":
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username = username, password = password)
        if user:
            login(request,user)
            return render(request,'index.html',{'info':'Welcome '+request.POST.get('username') +'!!!'})
        else:
            context['error'] = 'Provide valid credentials!!!'
            return render(request,'signin.html',context)
    else:
        return render(request,'signin.html',context)
    return render(request,'signin.html',context)
def sendandemail(request):
    try:
        if request.method == "POST":
            to = request.POST.get('email')
            fullname = request.POST.get('fullname')
            phonenumber = str(request.POST.get('phonenumber'))
            message = request.POST.get('message')
            content = 'Hii,'+'\n'+'Eduglobal9 Enquiry Room '+'\n'+'* '+ fullname+' wants a quick enquiry. '+'\n'+'* '+'His/Her phone number is  '+phonenumber+'\n'+'* '+'He has sent the message as: '+'\n'+ message
            send_mail(
                "Eduglobal9 Enquiry Room",
                content,
                settings.EMAIL_HOST_USER,
                [to]
                )
            return render(request,'index.html',{'info':'Email has been sent successfully'})
        else:
            return render(request,'index.html',{'erro':'Problem in sending email...'})
    except:
        return render(request,'index.html',{'erro':'Problem in sending email...'})
def logout_user(request):
    if request.method=='POST':
        logout(request)
        return HttpResponseRedirect(reverse('signin'))
def contact_employee(request):
    try:
        if request.method == "POST":
            to = request.POST.get('email')
            name = request.POST.get('name')
            subject = request.POST.get('subject')
            message = request.POST.get('message')
            content = 'Respected sir, '+'\n'+'My name is '+name+' The reason for contacting you is\n '+message
            send_mail(
                 subject,
                content,
                settings.EMAIL_HOST_USER,
                [to]
                )
            return render(request,'contact.html',{'info':'Email has been sent successfully'})
        else:
            return render(request,'contact.html',{'err':'Problem in sending email...'})
    except:
        return render(request,'contact.html',{'err':'Problem in sending email...'})


class PasswordContextMixin:
    extra_context = None

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update({
            'title': self.title,
            **(self.extra_context or {})
        })
        return context


class PasswordResetView(PasswordContextMixin, FormView):
    email_template_name = 'registration/password_reset_email.html'
    extra_email_context = None
    form_class = PasswordResetForm
    from_email = None
    html_email_template_name = None
    subject_template_name = 'registration/password_reset_subject.txt'
    success_url = reverse_lazy('password_reset_done')
    template_name = 'registration/password_reset_form.html'
    title = _('Password reset')
    token_generator = default_token_generator

    @method_decorator(csrf_protect)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def form_valid(self, form):
        opts = {
            'use_https': self.request.is_secure(),
            'token_generator': self.token_generator,
            'from_email': self.from_email,
            'email_template_name': self.email_template_name,
            'subject_template_name': self.subject_template_name,
            'request': self.request,
            'html_email_template_name': self.html_email_template_name,
            'extra_email_context': self.extra_email_context,
        }
        form.save(**opts)
        return super().form_valid(form)


INTERNAL_RESET_SESSION_TOKEN = '_password_reset_token'


class PasswordResetDoneView(PasswordContextMixin, TemplateView):
    template_name = 'registration/password_reset_done.html'
    title = _('Password reset sent')


class PasswordResetConfirmView(PasswordContextMixin, FormView):
    form_class = SetPasswordForm
    post_reset_login = False
    post_reset_login_backend = None
    reset_url_token = 'set-password'
    success_url = reverse_lazy('password_reset_complete')
    template_name = 'registration/password_reset_confirm.html'
    title = _('Enter new password')
    token_generator = default_token_generator

    @method_decorator(sensitive_post_parameters())
    @method_decorator(never_cache)
    def dispatch(self, *args, **kwargs):
        assert 'uidb64' in kwargs and 'token' in kwargs

        self.validlink = False
        self.user = self.get_user(kwargs['uidb64'])

        if self.user is not None:
            token = kwargs['token']
            if token == self.reset_url_token:
                session_token = self.request.session.get(INTERNAL_RESET_SESSION_TOKEN)
                if self.token_generator.check_token(self.user, session_token):
                    # If the token is valid, display the password reset form.
                    self.validlink = True
                    return super().dispatch(*args, **kwargs)
            else:
                if self.token_generator.check_token(self.user, token):
                    # Store the token in the session and redirect to the
                    # password reset form at a URL without the token. That
                    # avoids the possibility of leaking the token in the
                    # HTTP Referer header.
                    self.request.session[INTERNAL_RESET_SESSION_TOKEN] = token
                    redirect_url = self.request.path.replace(token, self.reset_url_token)
                    return HttpResponseRedirect(redirect_url)

        # Display the "Password reset unsuccessful" page.
        return self.render_to_response(self.get_context_data())

    def get_user(self, uidb64):
        try:
            # urlsafe_base64_decode() decodes to bytestring
            uid = urlsafe_base64_decode(uidb64).decode()
            user = UserModel._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist, ValidationError):
            user = None
        return user

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.user
        return kwargs

    def form_valid(self, form):
        user = form.save()
        del self.request.session[INTERNAL_RESET_SESSION_TOKEN]
        if self.post_reset_login:
            auth_login(self.request, user, self.post_reset_login_backend)
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if self.validlink:
            context['validlink'] = True
        else:
            context.update({
                'form': None,
                'title': _('Password reset unsuccessful'),
                'validlink': False,
            })
        return context


class PasswordResetCompleteView(PasswordContextMixin, TemplateView):
    template_name = 'registration/password_reset_complete.html'
    title = _('Password reset complete')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['login_url'] = resolve_url(settings.LOGIN_URL)
        return context


class PasswordChangeView(PasswordContextMixin, FormView):
    form_class = PasswordChangeForm
    success_url = reverse_lazy('password_change_done')
    template_name = 'registration/password_change_form.html'
    title = _('Password change')

    @method_decorator(sensitive_post_parameters())
    @method_decorator(csrf_protect)
    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs

    def form_valid(self, form):
        form.save()
        # Updating the password logs out all other sessions for the user
        # except the current one.
        update_session_auth_hash(self.request, form.user)
        return super().form_valid(form)


class PasswordChangeDoneView(PasswordContextMixin, TemplateView):
    template_name = 'registration/password_change_done.html'
    title = _('Password change successful')

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

def forget(request):
    if request.method == 'POST':
        e = request.POST.get('email')
        try:
            u = User.objects.get(username=request.POST.get('username'))
            u.set_password(request.POST.get('password'))
            content = 'Hey '+ request.POST.get('username') + '\n' + ' Your new Password is '+ request.POST.get('password') + '\n'+ 'Please do not share it with anyone.'
            send_mail(
                    'Eduglobal9 Revcovery Management System',
                
                    content,
                
                    settings.EMAIL_HOST_USER,

                    [e]                

                )
            u.save()
            return render(request,'signin.html',{'message':'Your password has been recovered successfully!!! Please check your email...'})
        except:
            return render(request,'signin.html',{'errormessage':'Validation Issue! Please Recheck once.'})
        
    

def subscribe(request):
    subject = "Eduglobal9 Newsletter"
    body = 'Hey '+request.POST.get('username')+','+'\n'+'Thank you for seeking an interest in us'+'\n'+'\n'+'Please find the attachment'+'\n'+'~Regards'+'\n'+'Team Eduglobal9'
    sender_email = "youremail@gmail.com"
    receiver_email = request.POST.get('email')
    password ="yourpassword"

    # Create a multipart message and set headers
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject
    message["Bcc"] = receiver_email  # Recommended for mass emails

# Add body to email
    message.attach(MIMEText(body, "plain"))

    filename = "Eduglobel9.pdf"  # In same directory as script

    # Open PDF file in binary mode
    with open(filename, "rb") as attachment:
        # Add file as application/octet-stream
        # Email client can usually download this automatically as attachment
        part = MIMEBase("application", "octet-stream")
        part.set_payload(attachment.read())

    # Encode file in ASCII characters to send by email    
    encoders.encode_base64(part)

    # Add header as key/value pair to attachment part
    part.add_header(
        "Content-Disposition",
        f"attachment; filename= {filename}",
    )

    # Add attachment to message and convert message to string
    message.attach(part)
    text = message.as_string()
    try:
        # Log in to server using secure context and send email
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, text)
        return render(request,'index.html',{'emailsent':'Your newsletter has been sent successfully. Please check your email!!!'})
    except:
        return render(request,'index.html',{'erroremailsent':'Validation Issues..Resend Email!!!'})
def poltava(request):
    return render(request,'poltava.html')
def vinista(request):
    return render(request,'vinnista.html')
def kharkiv(request):
    return render(request,'kharkiv.html')
def ternopil(request):
    return render(request,'ternopil.html')
def gallery(request):
    return render(request,'gallery.html')
def developer(request):
    return render(request,'developer.html')