// Vulnerable: Angular + Vue specific issues (TypeScript)
import { Component, OnInit } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';
import { HttpClient } from '@angular/common/http';

@Component({
  selector: 'app-user-profile',
  template: `<div [innerHTML]="trustedHtml"></div>`
})
export class UserProfileComponent implements OnInit {
  trustedHtml: SafeHtml;

  constructor(
    private sanitizer: DomSanitizer,
    private http: HttpClient
  ) {}

  ngOnInit(): void {
    // Angular: bypassing security
    const userInput = '<script>alert("xss")</script>';
    this.trustedHtml = this.sanitizer.bypassSecurityTrustHtml(userInput);
  }

  loadScript(url: string): void {
    const trustedUrl = this.sanitizer.bypassSecurityTrustResourceUrl(url);
  }
}

// Vue: v-html equivalent in JSX render function
const VueComponent = {
  props: ['htmlContent'],
  render(h: any) {
    return h('div', {
      domProps: {
        innerHTML: this.htmlContent
      }
    });
  }
};

// Hardcoded secret in TypeScript
const API_TOKEN: string = 'ghp_FAKE_TOKEN_TEST_GITHUB_TOKEN_FOR_TESTING_123412';
const encryption_key: string = 'AES256SecretEncryptionKey2024!@#';

export { UserProfileComponent, VueComponent };
