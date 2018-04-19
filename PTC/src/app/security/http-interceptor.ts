import { Injectable, NgModule } from '@angular/core';
import { HttpInterceptor, HttpHandler, HttpEvent, HttpRequest, HTTP_INTERCEPTORS } from '@angular/common/http';
import { Observable } from 'rxjs/Observable';

@Injectable()
export class HttpRequestInterceptor implements HttpInterceptor {
    intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
        const token = localStorage.getItem('bearerToken');
        if (token) {
            const newReq = req.clone(
                {
                    headers: req.headers.set('Authorization', 'Bearer ' + token)
                });

            return next.handle(newReq);
        }

        return next.handle(req);
    }
}

@NgModule({
    providers: [{
        provide: HTTP_INTERCEPTORS,
        useClass: HttpRequestInterceptor,
        multi: true
    }]
})
export class HttpInterceptorModule { }
