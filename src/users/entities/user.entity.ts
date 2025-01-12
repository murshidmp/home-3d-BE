import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, DeleteDateColumn, OneToMany, BeforeInsert, BeforeUpdate} from 'typeorm';
  @Entity()
  export class User {
    @PrimaryGeneratedColumn()
    id!: number;
  
    @Column({ type: 'varchar', nullable: false })
    username!: string;
  
    @Column({ type: 'date', nullable: false })
    dob!: Date;
  
    @Column({ type: 'enum', nullable: false, enum: ['male','female','other','no answer']})
    gender?: string;
  
    @Column({ type: 'varchar', nullable: true })
    residence!: string
  
    @Column({ type: 'varchar', nullable: false })
    email!: string;
   
    @Column({ type: 'varchar', nullable: false })
    password!: string;
  
    @Column({ type: 'boolean', default: true })
    active: boolean;
  
    @Column({ type: 'varchar', nullable: true })
    resetPasswordToken?: string;
  
    @Column({ type: 'varchar', nullable: true })
    refreshToken?: string;
  
    @Column({ type: 'varchar', nullable: true })
    deviceToken?: string;
  
    @Column({nullable: true})
    profile_image: string
  
    @Column({nullable: true})
    bio: string
  
    @CreateDateColumn({ type: 'timestamp' })
    createdAt!: Date;
  
    @UpdateDateColumn({ type: 'timestamp' })
    updatedAt!: Date;
  
    @DeleteDateColumn({ type: 'timestamp', nullable: true })
    deletedAt: Date;
    
      // Custom setter for email property
    set _email(value: string) {
      this.email = value.toLowerCase();
    }
   
    // Custom getter for email property
    get _email(): string {
      return this.email;
    }  
  
    @BeforeInsert()
    @BeforeUpdate()
    private updateEmailToLowercase() {
      if (this.email) {
        this.email = this.email.toLowerCase();
      }
    }
  }
  