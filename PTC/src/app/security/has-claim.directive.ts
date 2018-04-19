import { Directive, Input, TemplateRef, ViewContainerRef } from '@angular/core';
import { SecurityService } from './security.service';

@Directive({
  // tslint:disable-next-line:directive-selector
  selector: '[hasClaim]'
})
export class HasClaimDirective {

  constructor(private templateRef: TemplateRef<any>,
    private viewContainer: ViewContainerRef,
    private securityService: SecurityService) { }

  @Input() set hasClaim(claimType: any) {
    if (this.securityService.hasClaim(claimType)) {
      this.viewContainer.createEmbeddedView(this.templateRef);
    } else {
      this.viewContainer.clear();
    }
  }
}
