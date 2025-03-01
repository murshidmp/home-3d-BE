import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, OneToMany, CreateDateColumn, UpdateDateColumn, DeleteDateColumn } from 'typeorm';
import { User } from '../../user/entities/user.entity';
import { Post } from '../../post/entities/post.entity';

@Entity('projects')
export class Project {
  @PrimaryGeneratedColumn()
  id: number; // This will be an INT by default

  @ManyToOne(() => User, (user) => user.projects, { onDelete: 'CASCADE' })
  user: User;

  @Column()
  name: string;

  @Column({ nullable: true })
  description: string;

  @Column({ type: 'jsonb' })
  data: object;

  @Column({ default: false })
  isRendered: boolean;

  @Column({ default: 0 })
  renderCount: number;

  @OneToMany(() => Post, (post) => post.project)
  posts: Post[];

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  /**
   * When you add @DeleteDateColumn, TypeORM can use "soft delete" 
   * (the record is marked deleted but not physically removed).
   * If you call repository.softRemove(...), it sets the deletedAt value.
   */
  @DeleteDateColumn()
  deletedAt?: Date;
}
